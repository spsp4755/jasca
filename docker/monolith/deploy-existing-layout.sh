#!/bin/bash
set -euo pipefail

# Deploy JASCA using an editable host-path layout config.
# Copy deploy-existing-layout.env.example to deploy-existing-layout.env, edit values,
# then run this script.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/deploy-existing-layout.env}"
ENV_EXAMPLE="${ENV_EXAMPLE:-$SCRIPT_DIR/deploy-existing-layout.env.example}"

if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        echo "Created editable config: $ENV_FILE"
        echo "Edit this file for your server, then run this script again."
        exit 1
    fi

    echo "Error: config file not found: $ENV_FILE"
    echo "Create it from deploy-existing-layout.env.example and run again."
    exit 1
fi

set -a
# shellcheck source=/dev/null
. "$ENV_FILE"
set +a

APP_DIR="${APP_DIR:-/app/jasca}"
IMAGE_ARCHIVE="${IMAGE_ARCHIVE:-$SCRIPT_DIR/jasca-offline.tar.gz}"
IMAGE_TAR="${IMAGE_TAR:-$SCRIPT_DIR/jasca-offline.tar}"
IMAGE_NAME="${IMAGE_NAME:-jasca-offline:latest}"
CONTAINER_NAME="${CONTAINER_NAME:-jasca}"
WEB_PORT="${WEB_PORT:-3005}"
API_PORT="${API_PORT:-3001}"
EXPOSE_API_PORT="${EXPOSE_API_PORT:-0}"
CORS_ORIGIN="${CORS_ORIGIN:-}"
JWT_SECRET="${JWT_SECRET:-}"
DB_PASSWORD="${DB_PASSWORD:-}"
DATABASE_URL="${DATABASE_URL:-}"
REDIS_URL="${REDIS_URL:-redis://localhost:6379}"
TRIVY_CACHE_MOUNT="${TRIVY_CACHE_MOUNT:-}"
TRIVY_UPLOAD_MAX_BYTES="${TRIVY_UPLOAD_MAX_BYTES:-}"
SYFT_BINARY_PATH="${SYFT_BINARY_PATH:-}"
TRIVY_RPM_OS_FAMILY="${TRIVY_RPM_OS_FAMILY:-}"
TRIVY_RPM_OS_VERSION="${TRIVY_RPM_OS_VERSION:-}"
SCAN_RESULT_RETENTION_DAYS="${SCAN_RESULT_RETENTION_DAYS:-0}"
HOSTS_MOUNT="${HOSTS_MOUNT:-/etc/hosts}"
EXTRA_HOSTS="${EXTRA_HOSTS:-}"

if [ -z "$CORS_ORIGIN" ]; then
    echo "Error: CORS_ORIGIN must be set in $ENV_FILE"
    exit 1
fi

if [ -z "$JWT_SECRET" ]; then
    echo "Error: JWT_SECRET must be set in $ENV_FILE"
    exit 1
fi

if [ -z "$DB_PASSWORD" ]; then
    echo "Error: DB_PASSWORD must be set in $ENV_FILE"
    exit 1
fi

DATABASE_URL="${DATABASE_URL:-postgresql://jasca:${DB_PASSWORD}@localhost:5432/jasca}"

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker command not found."
    exit 1
fi

mkdir -p "$APP_DIR/pgdata" "$APP_DIR/redis" "$APP_DIR/scan-results"

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
  -e "DB_PASSWORD=${DB_PASSWORD}"
  -e "REDIS_URL=${REDIS_URL}"
  -e "DATABASE_URL=${DATABASE_URL}"
  -e "SCAN_RESULT_DIR=/app/jasca/scan-results"
  -e "SCAN_RESULT_RETENTION_DAYS=${SCAN_RESULT_RETENTION_DAYS}"
  -v "${APP_DIR}/pgdata:/var/lib/postgresql/data"
  -v "${APP_DIR}/redis:/var/lib/redis"
  -v "${APP_DIR}/scan-results:/app/jasca/scan-results"
)

if [ -n "$TRIVY_RPM_OS_FAMILY" ]; then
    DOCKER_RUN_ARGS+=(-e "TRIVY_RPM_OS_FAMILY=${TRIVY_RPM_OS_FAMILY}")
fi

if [ -n "$TRIVY_RPM_OS_VERSION" ]; then
    DOCKER_RUN_ARGS+=(-e "TRIVY_RPM_OS_VERSION=${TRIVY_RPM_OS_VERSION}")
fi

if [ -n "$TRIVY_UPLOAD_MAX_BYTES" ]; then
    DOCKER_RUN_ARGS+=(-e "TRIVY_UPLOAD_MAX_BYTES=${TRIVY_UPLOAD_MAX_BYTES}")
fi

if [ -n "$SYFT_BINARY_PATH" ]; then
    DOCKER_RUN_ARGS+=(-e "SYFT_BINARY_PATH=${SYFT_BINARY_PATH}")
fi

if [ "$EXPOSE_API_PORT" = "1" ]; then
    DOCKER_RUN_ARGS+=(-p "${API_PORT}:3001")
fi

if [ -f "$HOSTS_MOUNT" ]; then
    DOCKER_RUN_ARGS+=(-v "${HOSTS_MOUNT}:/etc/hosts:ro")
fi

if [ -n "$EXTRA_HOSTS" ]; then
    IFS=',' read -r -a EXTRA_HOST_ENTRIES <<< "$EXTRA_HOSTS"
    for host_entry in "${EXTRA_HOST_ENTRIES[@]}"; do
        if [ -n "$host_entry" ]; then
            DOCKER_RUN_ARGS+=(--add-host "$host_entry")
        fi
    done
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
echo "Web: ${CORS_ORIGIN} or http://localhost:${WEB_PORT}"
echo "Container API port: ${API_PORT} (set EXPOSE_API_PORT=1 to publish it on the host)"
echo "Data directory: ${APP_DIR}"
echo "Logs: docker logs -f ${CONTAINER_NAME}"
