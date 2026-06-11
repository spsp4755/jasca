#!/bin/sh
set -eu

IMAGE_NAME="${IMAGE_NAME:-jasca-offline:latest}"
BUNDLE_NAME="${BUNDLE_NAME:-jasca-offline-$(date +%Y%m%d-%H%M%S)}"
OUTPUT_DIR="${OUTPUT_DIR:-dist/offline-bundle}"
SKIP_BUILD="${SKIP_BUILD:-0}"
KEEP_TAR="${KEEP_TAR:-0}"
DOCKER_CONTEXT="${DOCKER_CONTEXT:-}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
BUNDLE_PATH="$PROJECT_ROOT/$OUTPUT_DIR/$BUNDLE_NAME"
IMAGE_TAR="$BUNDLE_PATH/jasca-offline.tar"
IMAGE_TAR_GZ="$IMAGE_TAR.gz"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker command not found. Install and start Docker before building the offline bundle." >&2
    exit 1
fi

docker_cmd() {
    if [ -n "$DOCKER_CONTEXT" ]; then
        docker --context "$DOCKER_CONTEXT" "$@"
    else
        docker "$@"
    fi
}

mkdir -p "$PROJECT_ROOT/trivy-db"
if [ ! -f "$PROJECT_ROOT/trivy-db/db/trivy.db" ]; then
    echo "[INFO] Trivy DB was not found at trivy-db/db/trivy.db." >&2
    echo "       This bundle expects the target server's Trivy cache to be mounted with start.sh/start.ps1." >&2
fi
mkdir -p "$BUNDLE_PATH"

cd "$PROJECT_ROOT"

if [ "$SKIP_BUILD" != "1" ]; then
    echo "Building Docker image: $IMAGE_NAME"
    docker_cmd build -f docker/monolith/Dockerfile -t "$IMAGE_NAME" .
else
    echo "Skipping Docker build. Using existing image: $IMAGE_NAME"
fi

echo "Saving Docker image to $IMAGE_TAR"
docker_cmd save "$IMAGE_NAME" -o "$IMAGE_TAR"

echo "Compressing image to $IMAGE_TAR_GZ"
gzip -c "$IMAGE_TAR" > "$IMAGE_TAR_GZ"

if [ "$KEEP_TAR" != "1" ]; then
    rm -f "$IMAGE_TAR"
fi

cp docker/monolith/start.sh "$BUNDLE_PATH/start.sh"
cp docker/monolith/start.ps1 "$BUNDLE_PATH/start.ps1"
cp docker/monolith/README-OFFLINE.md "$BUNDLE_PATH/README-OFFLINE.md"
chmod +x "$BUNDLE_PATH/start.sh"

cat > "$BUNDLE_PATH/manifest.json" <<EOF
{
  "name": "JASCA offline deployment bundle",
  "image": "$IMAGE_NAME",
  "archive": "jasca-offline.tar.gz",
  "createdAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "webPort": 3000,
  "apiPort": 3001,
  "includesTrivyCli": true,
  "dockerContext": "$DOCKER_CONTEXT",
  "trivyDbPathInImage": "/app/trivy-db",
  "supportsHostTrivyCacheMount": true,
  "notes": [
    "Transfer this whole directory to the closed network.",
    "Run ./start.sh on Linux or .\\\\start.ps1 on Windows.",
    "If Trivy is already installed on the server, mount its cache with TRIVY_CACHE_MOUNT or -TrivyCacheMount.",
    "Docker must be installed on the target host.",
    "The container preserves Docker volumes jasca_postgres_data and jasca_redis_data."
  ]
}
EOF

echo
echo "Offline bundle created:"
echo "  $BUNDLE_PATH"
echo
echo "Transfer the entire folder to the closed network."
