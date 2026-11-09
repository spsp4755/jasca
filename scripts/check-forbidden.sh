#!/bin/sh
# Fails if any forbidden word (case-insensitive, whole words; binaries skipped) appears in tracked files, web/dist or, when given, a built image.
# Usage: sh scripts/check-forbidden.sh [image:tag]
set -eu
LIST=${FORBIDDEN_WORDS:-$HOME/.config/jasca/forbidden-words.txt}
{ [ -f "$LIST" ] && grep -q '[^[:space:]]' "$LIST"; } || { echo "forbidden-words list missing or empty: $LIST" >&2; exit 1; }
cd "$(dirname "$0")/.."
# blank lines would match everything under grep -F, so use a cleaned copy
CLEAN=$(mktemp); trap 'rm -f "$CLEAN"' EXIT
grep '[^[:space:]]' "$LIST" > "$CLEAN"; LIST=$CLEAN
fail=0
# grep exit 1 = no match (fine); >=2 = error (fail). Prints matches on stdout.
scan() {
  rc=0; out=$("$@") || rc=$?
  [ "$rc" -le 1 ] || { echo "grep failed (exit $rc): $*" >&2; exit 1; }
  [ -z "$out" ] || { echo "$LABEL:"; echo "$out"; fail=1; }
}
LABEL="tracked files"; scan git grep -nwIiF -f "$LIST"
if [ -d web/dist ]; then LABEL="web/dist"; scan grep -rnwIiF -f "$LIST" web/dist; fi
if [ -n "${1:-}" ]; then
  # a scratch image cannot be run or listed, so unpack the layers named in manifest.json (legacy and OCI-layout saves) and grep the text files
  tmp=$(mktemp -d); trap 'rm -rf "$tmp" "$CLEAN"' EXIT
  mkdir "$tmp/img" "$tmp/fs"
  "${CONTAINER_ENGINE:-docker}" save "$1" | tar -x -C "$tmp/img"
  n=0
  for l in $(python3 -I -c 'import json,sys;[print(x) for m in json.load(open(sys.argv[1])) for x in m["Layers"]]' "$tmp/img/manifest.json"); do
    tar -x -C "$tmp/fs" -f "$tmp/img/$l" 2>/dev/null || true # device nodes and the like cannot be extracted unprivileged
    n=$((n+1))
  done
  [ "$n" -gt 0 ] && [ -n "$(ls -A "$tmp/fs")" ] || { echo "image $1: no layers extracted, cannot scan" >&2; exit 1; }
    # keep grep's own exit status (a pipe into sed would hide a grep error)
  LABEL="image $1"; scan sh -c 'out=$(grep -rnwIiF -f "$1" "$2" "$3"); rc=$?; [ -z "$out" ] || printf "%s\n" "$out" | sed "s#^$4/##"; exit $rc' _ "$LIST" "$tmp/fs" "$tmp/img" "$tmp"
fi
[ "$fail" -eq 0 ] || exit 1
echo "forbidden-words check: clean"
