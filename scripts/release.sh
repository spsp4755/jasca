#!/bin/sh
# Offline release: service image + PostgreSQL image + k8s yaml + docs + SHA256SUMS in release/.
# Usage: sh scripts/release.sh v1.0.0   (CONTAINER_ENGINE=podman to use Podman)
# Needs RELEASE-NOTES.md (this version only) and a PostgreSQL for tests (JASCA_TEST_DATABASE_URL, default: the dev jasca-pg container).
# Pushing and `gh release` happen outside this script.
set -eu
TAG=${1:?usage: release.sh vX.Y.Z}
ENGINE=${CONTAINER_ENGINE:-docker}
PG=postgres:v17.11-jasca1 # built from deploy/postgres.Dockerfile; a new name, so nodes do not keep an older image under the old tag
cd "$(dirname "$0")/.."
[ -z "$(git status --porcelain)" ] || { echo "working tree is not clean" >&2; exit 1; }
[ -f RELEASE-NOTES.md ] || { echo "RELEASE-NOTES.md missing" >&2; exit 1; }
grep -Fq "image: jasca:v" deploy/jasca.yaml || { echo "deploy/jasca.yaml has no image: jasca:vX line" >&2; exit 1; }
sh scripts/check-forbidden.sh
export JASCA_TEST_DATABASE_URL=${JASCA_TEST_DATABASE_URL:-postgres://jasca:jasca-dev-pw@127.0.0.1:55440/jasca_release}
"$ENGINE" exec jasca-pg createdb -U jasca jasca_release 2>/dev/null || true
go vet ./... && go test ./...
(cd web && npm ci && npm run build)
rm -rf release && mkdir release
"$ENGINE" build --platform linux/amd64 --build-arg VERSION="${TAG#v}" -t "jasca:$TAG" .
sh scripts/check-forbidden.sh "jasca:$TAG"
"$ENGINE" save "jasca:$TAG" | gzip -n > "release/jasca-$TAG.tar.gz"
"$ENGINE" image inspect "$PG" >/dev/null 2>&1 || "$ENGINE" build --pull --platform linux/amd64 -f deploy/postgres.Dockerfile -t "$PG" deploy
"$ENGINE" save "$PG" | gzip -n > release/postgres-v17.11-jasca1.tar.gz
sed "s#image: jasca:v[0-9][^ ]*#image: jasca:$TAG#; s#^\# JASCA v[0-9][^ ]*#\# JASCA $TAG#" deploy/jasca.yaml > release/jasca.yaml
cp deploy/postgres.yaml DEPLOY-OFFLINE.md RELEASE-NOTES.md release/
(cd release && sha256sum "jasca-$TAG.tar.gz" postgres-v17.11-jasca1.tar.gz jasca.yaml postgres.yaml DEPLOY-OFFLINE.md RELEASE-NOTES.md > SHA256SUMS)
ls -l release
