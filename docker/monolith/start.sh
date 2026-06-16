#!/bin/bash
set -euo pipefail

# Load and run JASCA in an offline environment.
# Usage: ./start.sh [bundle-image.tar.gz|bundle-image.tar]

IMAGE_ARCHIVE="${1:-jasca-offline.tar.gz}"
IMAGE_TAR="jasca-offline.tar"
IMAGE_NAME="${IMAGE_NAME:-jasca-offline:latest}"
CONTAINER_NAME="${CONTAINER_NAME:-jasca}"
WEB_PORT="${WEB_PORT:-3000}"
API_PORT="${API_PORT:-3001}"
TRIVY_CACHE_MOUNT="${TRIVY_CACHE_MOUNT:-}"
JWT_SECRET="${JWT_SECRET:-}"
DB_PASSWORD="${DB_PASSWORD:-}"
CORS_ORIGIN="${CORS_ORIGIN:-http://localhost:${WEB_PORT}}"

if [ -z "$JWT_SECRET" ]; then
    echo "Error: JWT_SECRET must be set, for example: JWT_SECRET='<long-random-secret>' ./start.sh"
    exit 1
fi

if [ -z "$DB_PASSWORD" ]; then
    echo "Error: DB_PASSWORD must be set, for example: DB_PASSWORD='<database-password>' ./start.sh"
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker command not found."
    exit 1
fi

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

echo "Ensuring persistent Docker volumes exist..."
docker volume create jasca_postgres_data >/dev/null
docker volume create jasca_redis_data >/dev/null

if [ "$(docker ps -aq -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "Replacing existing container: $CONTAINER_NAME"
    docker stop "$CONTAINER_NAME" >/dev/null || true
    docker rm "$CONTAINER_NAME" >/dev/null || true
fi

echo "Starting JASCA container..."
DOCKER_RUN_ARGS=(
  -d
  --name "$CONTAINER_NAME"
  --restart unless-stopped
  -p "${WEB_PORT}:3000"
  -p "${API_PORT}:3001"
  -e "JWT_SECRET=${JWT_SECRET}"
  -e "DB_PASSWORD=${DB_PASSWORD}"
  -e "CORS_ORIGIN=${CORS_ORIGIN}"
  -v jasca_postgres_data:/var/lib/postgresql/data
  -v jasca_redis_data:/var/lib/redis
)

if [ -n "$TRIVY_CACHE_MOUNT" ]; then
    if [ ! -d "$TRIVY_CACHE_MOUNT" ]; then
        echo "Error: TRIVY_CACHE_MOUNT does not exist or is not a directory: $TRIVY_CACHE_MOUNT"
        exit 1
    fi
    echo "Mounting host Trivy cache: $TRIVY_CACHE_MOUNT -> /app/trivy-db"
    DOCKER_RUN_ARGS+=(-v "${TRIVY_CACHE_MOUNT}:/app/trivy-db:ro")
fi

docker run "${DOCKER_RUN_ARGS[@]}" "$IMAGE_NAME"

echo "JASCA is running."
echo "Web: http://localhost:${WEB_PORT}"
echo "API: http://localhost:${API_PORT}"
echo "Logs: docker logs -f ${CONTAINER_NAME}"
