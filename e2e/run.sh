#!/bin/sh
# Builds JASCA, wipes the test database, sets up Keycloak and Trivy, then runs the browser suites in order. See README.md.
#   sh e2e/run.sh              all suites
#   sh e2e/run.sh login admin  only these (login must come first on an empty database)
set -eu
cd "$(dirname "$0")"
if [ -f .env ]; then set -a; . ./.env; set +a; fi
: "${JASCA_E2E_ADMIN_PASSWORD:?e2e/.env에 JASCA_E2E_ADMIN_PASSWORD를 정하세요}"
: "${JASCA_E2E_DATABASE_URL:?}" "${JASCA_E2E_PG_CONTAINER:?}" "${JASCA_E2E_PG_USER:?}" "${JASCA_E2E_PG_DB:?}"
: "${JASCA_E2E_KC_CONTAINER:?}" "${JASCA_E2E_KC_ADMIN_PASSWORD:?}" "${JASCA_E2E_KC_USER_PASSWORD:?}" "${JASCA_E2E_KC_CLIENT_SECRET:?}" "${JASCA_E2E_KC_SYNC_SECRET:?}"
case "$JASCA_E2E_PG_DB" in *e2e*) ;; *) echo "JASCA_E2E_PG_DB($JASCA_E2E_PG_DB)에 e2e가 들어 있지 않습니다. 실행할 때마다 이 DB를 지우므로 시험용 DB만 쓰세요." >&2; exit 1;; esac
DOCKER=${JASCA_E2E_DOCKER:-docker}
ADDR=${JASCA_E2E_ADDR:-127.0.0.1:18301}
SUITES=${*:-login projects ingest mcp exceptions advisory scan trivydb admin fixes packages a11y console}
[ -d node_modules/axe-core ] || (npm install --no-audit --no-fund >/dev/null)
[ -z "${JASCA_E2E_LD_LIBRARY_PATH:-}" ] || export LD_LIBRARY_PATH="$JASCA_E2E_LD_LIBRARY_PATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export JASCA_E2E_BASE="${JASCA_E2E_BASE:-http://localhost:${ADDR##*:}}"
# .out/keep (Trivy binary, DB copy, DB bundle) survives between runs: the DB is 1.6GB
mkdir -p .out/keep; find .out -mindepth 1 -maxdepth 1 ! -name keep -exec rm -rf {} +
mkdir -p .out/shots

echo "== build"
(cd ../web && npx vite build >/dev/null)
(cd .. && go build -o e2e/.out/jasca .)

echo "== trivy"
KEEP=.out/keep; TRIVY=
if command -v "$DOCKER" >/dev/null 2>&1; then
  if [ ! -x $KEEP/trivy ]; then
    c=$("$DOCKER" create "${JASCA_E2E_TRIVY_IMAGE:-aquasec/trivy:0.76.1}") && "$DOCKER" cp "$c:/usr/local/bin/trivy" $KEEP/trivy >/dev/null; "$DOCKER" rm "$c" >/dev/null 2>&1 || true
  fi
  if [ ! -f $KEEP/db/trivy.db ]; then
    c=$("$DOCKER" create -v "${JASCA_E2E_TRIVY_VOLUME:-trivy-cache}:/c" alpine true) && "$DOCKER" cp "$c:/c/db" $KEEP/db >/dev/null; "$DOCKER" rm "$c" >/dev/null 2>&1 || true
  fi
  [ ! -f $KEEP/db/trivy.db ] || [ -f $KEEP/db.tar.gz ] || tar -C $KEEP/db -cf - trivy.db metadata.json | gzip -1 > $KEEP/db.tar.gz
fi
if [ -x $KEEP/trivy ] && [ -f $KEEP/db.tar.gz ]; then
  TRIVY=$PWD/$KEEP/trivy
  mkdir -p .out/data/trivy && cp -al $KEEP/db .out/data/trivy/db 2>/dev/null || cp -a $KEEP/db .out/data/trivy/db
  export JASCA_E2E_TRIVY_BUNDLE=$PWD/$KEEP/db.tar.gz
else
  echo "Trivy를 준비하지 못해 scan, trivydb 스위트를 건너뜁니다." >&2
  SUITES=$(echo " $SUITES " | sed 's/ scan / /; s/ trivydb / /')
fi

echo "== fresh database ($JASCA_E2E_PG_CONTAINER/$JASCA_E2E_PG_DB)"
"$DOCKER" exec "$JASCA_E2E_PG_CONTAINER" psql -q -v ON_ERROR_STOP=1 -U "$JASCA_E2E_PG_USER" -d "$JASCA_E2E_PG_DB" \
  -c "SET client_min_messages=warning; DROP SCHEMA public CASCADE; CREATE SCHEMA public;" >/dev/null

echo "== keycloak ($JASCA_E2E_KC_CONTAINER)"
"$DOCKER" exec -i -e KC_ADMIN_PASSWORD="$JASCA_E2E_KC_ADMIN_PASSWORD" -e KC_USER_PASSWORD="$JASCA_E2E_KC_USER_PASSWORD" \
  -e KC_CLIENT_SECRET="$JASCA_E2E_KC_CLIENT_SECRET" -e KC_SYNC_SECRET="$JASCA_E2E_KC_SYNC_SECRET" \
  -e "KC_REDIRECT_BASES=${JASCA_E2E_KC_REDIRECT_BASES:-http://localhost:${ADDR##*:}}" \
  "$JASCA_E2E_KC_CONTAINER" bash -s < keycloak-setup.sh > .out/keycloak.log 2>&1 || { cat .out/keycloak.log; exit 1; }

if curl -sf "$JASCA_E2E_BASE/healthz" >/dev/null 2>&1; then echo "$ADDR 에 이미 서버가 떠 있습니다. 끄고 다시 실행하세요." >&2; exit 1; fi
[ -z "$TRIVY" ] || export JASCA_TRIVY_BIN=$TRIVY
JASCA_MAX_SESSIONS=0 JASCA_SESSION_IDLE_MIN=0 JASCA_DATABASE_URL=$JASCA_E2E_DATABASE_URL JASCA_BOOTSTRAP_PASSWORD=$JASCA_E2E_ADMIN_PASSWORD \
  JASCA_ADDR=$ADDR JASCA_DATA_DIR=.out/data .out/jasca > .out/server.log 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null' EXIT INT TERM
up=
for i in $(seq 40); do curl -sf "$JASCA_E2E_BASE/healthz" >/dev/null && { up=1; break; }; sleep 0.5; done
[ -n "$up" ] || { echo "서버가 시작되지 않았습니다. 서버 로그:" >&2; cat .out/server.log >&2; exit 1; }

fail=0
printf '\n%-12s %-4s %s\n' 스위트 결과 확인수
for t in $SUITES; do
  if node "$t.cjs" > ".out/$t.log" 2>&1; then r=통과; else r=실패; fail=1; fi
  printf '%-12s %-4s %s개\n' "$t" "$r" "$(grep -c '^ok' ".out/$t.log" || true)"
  [ "$r" = 실패 ] && grep -v '^ok' ".out/$t.log" | tail -6 | sed 's/^/    /'
done
if [ $fail = 0 ]; then echo "전체 통과"; else echo "실패한 스위트가 있습니다. e2e/.out/*.log 참고"; fi
exit $fail
