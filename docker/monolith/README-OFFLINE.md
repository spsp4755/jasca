# JASCA Offline Deployment Instructions

This bundle is intended for closed-network deployment. It contains a Docker image archive, startup scripts, and this guide.

## Bundle Contents

- `jasca-offline.tar.gz`: Docker image archive.
- `start.sh`: Linux startup script.
- `start.ps1`: Windows PowerShell startup script.
- `manifest.json`: Bundle metadata.
- `README-OFFLINE.md`: This file.

The image is monolithic: it includes PostgreSQL, Redis, JASCA API, JASCA Web, and Trivy CLI. Trivy DB is not embedded by default to keep the bundle portable. If the target server already has Trivy DB cache, mount that cache into `/app/trivy-db`.

## Build the Bundle on an Online Build Machine

Optional: download Trivy DB on the target closed-network server or on a separate update machine. The recommended deployment path is to mount the server's Trivy cache when starting JASCA.

```powershell
.\script\download-trivy-db.ps1
```

Windows PowerShell:

```powershell
.\script\build-offline-bundle.ps1
```

Linux/macOS:

```bash
sh ./script/build-offline-bundle.sh
```

The generated folder is placed under `dist/offline-bundle/`. Transfer the entire generated folder to the closed network.

If no Trivy cache is mounted, direct file scans will return a clear "Trivy vulnerability DB is not available" error until the DB is provided.

## Use Trivy Already Installed on the Closed-Network Server

Docker containers cannot directly use a Trivy binary installed on the host unless you mount the binary and all of its runtime dependencies. The recommended setup is:

- Use the Trivy CLI already included in the JASCA image.
- Reuse the host server's existing Trivy DB/cache by mounting it into the container.

Common Linux cache locations:

```bash
$HOME/.cache/trivy
/root/.cache/trivy
```

The mounted directory must contain Trivy's cache layout, for example:

```text
db/trivy.db
db/metadata.json
java-db/trivy-java.db
java-db/metadata.json
```

Linux example:

```bash
TRIVY_CACHE_MOUNT=/root/.cache/trivy ./start.sh
```

Windows example:

```powershell
.\start.ps1 -TrivyCacheMount "$env:LOCALAPPDATA\trivy"
```

If you want to refresh the DB on the server before starting JASCA, run this on a machine where Trivy can access its configured update source:

```bash
trivy image --download-db-only
trivy image --download-java-db-only
```

## Deploy on a Closed-Network Linux Server

```bash
chmod +x start.sh
./start.sh
```

## Deploy on a Closed-Network Windows Server

```powershell
.\start.ps1
```

## Ports

- Web: `http://localhost:3000`
- API: `http://localhost:3001`
- Swagger: `http://localhost:3001/api/docs`

To change ports:

Linux:

```bash
WEB_PORT=8080 API_PORT=8081 ./start.sh
```

Windows:

```powershell
.\start.ps1 -WebPort 8080 -ApiPort 8081
```

## Data Persistence

The startup scripts preserve these Docker volumes:

- `jasca_postgres_data`
- `jasca_redis_data`

The scripts replace only the running container, not the persistent data volumes.

## Logs

```bash
docker logs -f jasca
```

## Manual Load/Run

Linux:

```bash
gzip -dc jasca-offline.tar.gz | docker load
docker volume create jasca_postgres_data
docker volume create jasca_redis_data
docker run -d --name jasca --restart unless-stopped \
  -p 3000:3000 \
  -p 3001:3001 \
  -v jasca_postgres_data:/var/lib/postgresql/data \
  -v jasca_redis_data:/var/lib/redis \
  -v /root/.cache/trivy:/app/trivy-db:ro \
  jasca-offline:latest
```

Windows PowerShell:

```powershell
.\start.ps1
```
