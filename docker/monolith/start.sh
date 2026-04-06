#!/bin/bash
set -euo pipefail

# Script to load and run JASCA in an offline environment without deleting existing data

IMAGE_TAR="${IMAGE_TAR:-jasca-offline.tar}"
IMAGE_NAME="${IMAGE_NAME:-jasca-offline:latest}"
CONTAINER_NAME="${CONTAINER_NAME:-jasca}"
POSTGRES_DATA_REF="${POSTGRES_DATA_REF:-}"
REDIS_DATA_REF="${REDIS_DATA_REF:-}"
DEFAULT_POSTGRES_VOLUME="jasca_postgres_data"
DEFAULT_REDIS_VOLUME="jasca_redis_data"

get_existing_container_id() {
    docker ps -aq --filter "name=^/${CONTAINER_NAME}$"
}

get_existing_mount_info() {
    local destination="$1"
    local container_id="$2"

    docker inspect --format "{{range .Mounts}}{{if eq .Destination \"$destination\"}}{{.Type}}|{{.Name}}|{{.Source}}{{end}}{{end}}" "$container_id" 2>/dev/null || true
}

resolve_storage_ref() {
    local destination="$1"
    local explicit_value="$2"
    local default_value="$3"

    if [ -n "$explicit_value" ]; then
        echo "$explicit_value"
        return
    fi

    if [ -n "${EXISTING_CONTAINER_ID:-}" ]; then
        local mount_info mount_type mount_name mount_source
        mount_info="$(get_existing_mount_info "$destination" "$EXISTING_CONTAINER_ID")"
        if [ -n "$mount_info" ]; then
            IFS='|' read -r mount_type mount_name mount_source <<< "$mount_info"
            if [ "$mount_type" = "volume" ] && [ -n "$mount_name" ]; then
                echo "$mount_name"
                return
            fi
            if [ "$mount_type" = "bind" ] && [ -n "$mount_source" ]; then
                echo "$mount_source"
                return
            fi
        fi
    fi

    echo "$default_value"
}

ensure_storage_exists() {
    local storage_ref="$1"

    if [[ "$storage_ref" == /* ]]; then
        mkdir -p "$storage_ref"
        return
    fi

    docker volume inspect "$storage_ref" >/dev/null 2>&1 || docker volume create "$storage_ref" >/dev/null
}

# 1. Load the image
if [ -f "$IMAGE_TAR" ]; then
    echo "removing old image..."
    docker rmi $IMAGE_NAME || true
    echo "Loading Docker image from $IMAGE_TAR..."
    docker load -i "$IMAGE_TAR"
else
    echo "Error: $IMAGE_TAR not found!"
    exit 1
fi

EXISTING_CONTAINER_ID="$(get_existing_container_id)"
POSTGRES_DATA_REF="$(resolve_storage_ref "/var/lib/postgresql/data" "$POSTGRES_DATA_REF" "$DEFAULT_POSTGRES_VOLUME")"
REDIS_DATA_REF="$(resolve_storage_ref "/var/lib/redis" "$REDIS_DATA_REF" "$DEFAULT_REDIS_VOLUME")"

echo "Using Postgres storage: $POSTGRES_DATA_REF"
echo "Using Redis storage: $REDIS_DATA_REF"

# 2. Prepare storage without deleting existing data
ensure_storage_exists "$POSTGRES_DATA_REF"
ensure_storage_exists "$REDIS_DATA_REF"

# 3. Stop and remove existing container if it exists
if [ -n "$EXISTING_CONTAINER_ID" ]; then
    echo "Stopping and removing existing container..."
    docker stop $CONTAINER_NAME
    docker rm $CONTAINER_NAME
fi

# 4. Run the container
echo "Starting JASCA container..."
docker run -d \
  --name $CONTAINER_NAME \
  --restart unless-stopped \
  -p 3000:3000 \
  -p 3001:3001 \
  -v "$POSTGRES_DATA_REF:/var/lib/postgresql/data" \
  -v "$REDIS_DATA_REF:/var/lib/redis" \
  $IMAGE_NAME

echo "JASCA is running!"
echo "Web: http://localhost:3000"
echo "API: http://localhost:3001"
