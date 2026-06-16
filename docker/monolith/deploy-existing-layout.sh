#!/bin/bash
set -euo pipefail

# Deploy JASCA using the same host-path layout as the existing closed-network server.
# Defaults intentionally match the current production-like command:
#   /app/jasca data directory, web port 3005, and https://jasca.koreacb.com CORS origin.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

APP_DIR="${APP_DIR:-/app/jasca}"
IMAGE_ARCHIVE="${IMAGE_ARCHIVE:-$SCRIPT_DIR/jasca-offline.tar.gz}"
IMAGE_TAR="${IMAGE_TAR:-$SCRIPT_DIR/jasca-offline.tar}"
IMAGE_NAME="${IMAGE_NAME:-jasca-offline:latest}"
CONTAINER_NAME="${CONTAINER_NAME:-jasca}"
WEB_PORT="${WEB_PORT:-3005}"
API_PORT="${API_PORT:-3001}"
EXPOSE_API_PORT="${EXPOSE_API_PORT:-0}"
CORS_ORIGIN="${CORS_ORIGIN:-https://jasca.koreacb.com}"
JWT_SECRET="${JWT_SECRET:-jasca_offline_secret}"
DATABASE_URL="${DATABASE_URL:-postgresql://jasca:jasca_secret@localhost:5432/jasca}"
REDIS_URL="${REDIS_URL:-redis://localhost:6379}"
TRIVY_CACHE_MOUNT="${TRIVY_CACHE_MOUNT:-}"
HOSTS_MOUNT="${HOSTS_MOUNT:-/etc/hosts}"

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker command not found."
    exit 1
fi

mkdir -p "$APP_DIR/pgdata" "$APP_DIR/redis"

if [ ! -f "$IMAGE_ARCHIVE" ]; then
    if [ -f "$IMAGE_TAR" ]; then
        IMAGE_ARCHIVE="$IMAGE_TAR"
    else
        echo "Error: image archive not found: $IMAGE_ARCHIVE"
        exit 1
    fi
fi

case "$IMAGE_ARCHIVE" in
    *.tar.gz|*.tgz)
        echo "Loading Docker image from compressed archive: $IMAGE_ARCHIVE"
        gzip -dc "$IMAGE_ARCHIVE" | docker load
        ;;
    *.tar)
        echo "Loading Docker image from archive: $IMAGE_ARCHIVE"
        docker load -i "$IMAGE_ARCHIVE"
        ;;
    *)
        echo "Error: unsupported archive extension. Use .tar or .tar.gz"
        exit 1
        ;;
esac

if [ "$(docker ps -aq -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "Replacing existing container: $CONTAINER_NAME"
    docker stop "$CONTAINER_NAME" >/dev/null || true
    docker rm "$CONTAINER_NAME" >/dev/null || true
fi

DOCKER_RUN_ARGS=(
  -d
  --name "$CONTAINER_NAME"
  --restart unless-stopped
  -p "${WEB_PORT}:3000"
  -e "CORS_ORIGIN=${CORS_ORIGIN}"
  -e "PORT=${API_PORT}"
  -e "JWT_SECRET=${JWT_SECRET}"
  -e "REDIS_URL=${REDIS_URL}"
  -e "DATABASE_URL=${DATABASE_URL}"
  -v "${APP_DIR}/pgdata:/var/lib/postgresql/data"
  -v "${APP_DIR}/redis:/var/lib/redis"
)

if [ "$EXPOSE_API_PORT" = "1" ]; then
    DOCKER_RUN_ARGS+=(-p "${API_PORT}:3001")
fi

if [ -f "$HOSTS_MOUNT" ]; then
    DOCKER_RUN_ARGS+=(-v "${HOSTS_MOUNT}:/etc/hosts:ro")
fi

if [ -n "$TRIVY_CACHE_MOUNT" ]; then
    if [ ! -d "$TRIVY_CACHE_MOUNT" ]; then
        echo "Error: TRIVY_CACHE_MOUNT does not exist or is not a directory: $TRIVY_CACHE_MOUNT"
        exit 1
    fi
    echo "Mounting host Trivy cache: $TRIVY_CACHE_MOUNT -> /app/trivy-db"
    DOCKER_RUN_ARGS+=(-v "${TRIVY_CACHE_MOUNT}:/app/trivy-db:ro")
fi

echo "Starting JASCA container with existing server layout..."
docker run "${DOCKER_RUN_ARGS[@]}" "$IMAGE_NAME"

echo "JASCA is running."
echo "Web: https://jasca.koreacb.com or http://localhost:${WEB_PORT}"
echo "Container API port: ${API_PORT} (set EXPOSE_API_PORT=1 to publish it on the host)"
echo "Data directory: ${APP_DIR}"
echo "Logs: docker logs -f ${CONTAINER_NAME}"
