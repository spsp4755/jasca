#!/bin/sh
# Fails if any forbidden word (case-insensitive) appears in tracked files, web/dist or, when given, a built image.
# Usage: sh scripts/check-forbidden.sh [image:tag]
set -eu
LIST=${FORBIDDEN_WORDS:-$HOME/.config/jasca/forbidden-words.txt}
[ -s "$LIST" ] || { echo "forbidden-words list missing or empty: $LIST" >&2; exit 1; }
cd "$(dirname "$0")/.."
fail=0
hits=$(git ls-files -z | xargs -0 grep -nIiF -f "$LIST" 2>/dev/null || true)
[ -z "$hits" ] || { echo "tracked files:"; echo "$hits"; fail=1; }
if [ -d web/dist ]; then
  hits=$(grep -rnIiF -f "$LIST" web/dist 2>/dev/null || true)
  [ -z "$hits" ] || { echo "web/dist:"; echo "$hits"; fail=1; }
fi
if [ -n "${1:-}" ]; then
  # a scratch image cannot be run or listed, so unpack the layers and grep the text files
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  mkdir "$tmp/img" "$tmp/fs"
  "${CONTAINER_ENGINE:-docker}" save "$1" | tar -x -C "$tmp/img"
  for l in $(find "$tmp/img" -type f \( -name layer.tar -o -name '*.tar' \)); do tar -x -C "$tmp/fs" -f "$l" 2>/dev/null || true; done
  hits=$(grep -rnIiF -f "$LIST" "$tmp/fs" "$tmp/img" 2>/dev/null | sed "s#$tmp/##" || true)
  [ -z "$hits" ] || { echo "image $1:"; echo "$hits"; fail=1; }
fi
[ "$fail" -eq 0 ] || exit 1
echo "forbidden-words check: clean"
