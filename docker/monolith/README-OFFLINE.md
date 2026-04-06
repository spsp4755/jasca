# JASCA Offline Deployment Instructions

## Important
- `v0.1.1` is designed to preserve existing data during offline upgrades.
- Do not use old scripts that delete Docker volumes before restarting the container.
- The bundled `start.sh` keeps existing Postgres and Redis storage and applies schema migrations on startup.

## Files to copy into the offline environment
- `jasca-offline.tar`
- `start.sh`
- `README-OFFLINE.md`

## Prerequisites
- Docker installed on the target machine.
- Enough disk space for the Docker image and existing data volumes.

## Recommended upgrade flow for an existing JASCA server
1. Copy the three files above to the offline server.
2. Make the script executable:
   ```bash
   chmod +x start.sh
   ```
3. If your current container name is `jasca`, run:
   ```bash
   ./start.sh
   ```
4. If your current container uses a different name, tell the script which container to upgrade:
   ```bash
   CONTAINER_NAME=my-jasca ./start.sh
   ```

The script will:
- load the new image from `jasca-offline.tar`
- detect the existing Postgres and Redis mounts from the running container
- stop and replace only the container
- keep the existing database and Redis data
- apply database migrations automatically during startup

## Fresh install flow
If this is a brand-new offline deployment with no existing container:
```bash
chmod +x start.sh
./start.sh
```

The script will create default storage named `jasca_postgres_data` and `jasca_redis_data`.

## Optional: explicit storage override
If you want to force a specific volume name or bind mount path, you can pass it in:
```bash
POSTGRES_DATA_REF=jasca_postgres_data REDIS_DATA_REF=jasca_redis_data ./start.sh
```

Example with bind mounts:
```bash
POSTGRES_DATA_REF=/srv/jasca/postgres REDIS_DATA_REF=/srv/jasca/redis ./start.sh
```

## Manual steps
1. Load the image:
   ```bash
   docker load -i jasca-offline.tar
   ```
2. Find the current container and mounts if you are upgrading:
   ```bash
   docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
   docker inspect jasca --format '{{range .Mounts}}{{println .Type ":" .Name ":" .Source "->" .Destination}}{{end}}'
   ```
3. Stop and remove only the application container:
   ```bash
   docker stop jasca
   docker rm jasca
   ```
4. Start the new image with the same storage:
   ```bash
   docker run -d --name jasca \
     --restart unless-stopped \
     -p 3000:3000 \
     -p 3001:3001 \
     -v jasca_postgres_data:/var/lib/postgresql/data \
     -v jasca_redis_data:/var/lib/redis \
     jasca-offline:latest
   ```

## Verification
After startup, check logs:
```bash
docker logs -f jasca
```

Expected behavior on upgrade:
- existing data remains available
- database migration runs once
- web UI opens on `http://<server>:3000`
