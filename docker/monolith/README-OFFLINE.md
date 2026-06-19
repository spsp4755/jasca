# JASCA 폐쇄망 배포 안내

이 번들은 폐쇄망 환경에서 JASCA를 배포하기 위한 오프라인 배포 패키지입니다. Docker 이미지 아카이브, 실행 스크립트, 환경 설정 예시 파일, 배포 안내 문서를 포함합니다.

## 번들 구성

- `jasca-offline.tar.gz`: Docker 이미지 아카이브
- `start.sh`: Linux 기본 실행 스크립트
- `start.ps1`: Windows PowerShell 기본 실행 스크립트
- `deploy-existing-layout.sh`: host-path 기반 Linux 배포 스크립트
- `deploy-existing-layout.env.example`: 운영 환경 설정 템플릿
- `manifest.json`: 번들 메타데이터
- `README-OFFLINE.md`: 이 문서

Docker 이미지는 PostgreSQL, Redis, JASCA API, JASCA Web, Trivy CLI를 한 컨테이너 안에 포함합니다. Trivy DB는 이미지에 기본 포함하지 않습니다. 폐쇄망 서버에 이미 존재하는 Trivy 캐시를 `/app/trivy-db`로 마운트해서 사용하는 방식을 권장합니다.

## 온라인 빌드 장비에서 번들 생성

Windows PowerShell:

```powershell
.\script\build-offline-bundle.ps1
```

Linux 또는 macOS:

```bash
sh ./script/build-offline-bundle.sh
```

생성된 번들은 `dist/offline-bundle/` 아래에 만들어집니다. 생성된 폴더 또는 `*-bundle.tar.gz` 파일을 폐쇄망으로 반입하면 됩니다.

Trivy DB가 마운트되지 않으면 파일 직접 스캔 시 `Trivy vulnerability DB is not available` 오류가 표시됩니다. 이 경우 Trivy 캐시 경로를 확인해 다시 마운트하세요.

## 폐쇄망 서버의 기존 Trivy 캐시 사용

컨테이너는 호스트에 설치된 Trivy 바이너리를 직접 사용하지 않습니다. 대신 JASCA 이미지에 포함된 Trivy CLI를 사용하고, 호스트 서버에 있는 Trivy DB/cache 디렉터리를 컨테이너로 마운트합니다.

일반적인 Linux Trivy 캐시 위치:

```bash
$HOME/.cache/trivy
/root/.cache/trivy
```

마운트할 디렉터리에는 다음과 같은 Trivy 캐시 구조가 있어야 합니다.

```text
db/trivy.db
db/metadata.json
java-db/trivy-java.db
java-db/metadata.json
```

DB를 미리 갱신해야 한다면 Trivy가 업데이트 소스에 접근 가능한 서버에서 아래 명령을 실행하세요.

```bash
trivy image --download-db-only
trivy image --download-java-db-only
```

## 기존 `/app/jasca` 구조로 배포

기존 운영 서버처럼 `/app/jasca/pgdata`, `/app/jasca/redis`를 host-path로 사용하고 웹 포트 `3005`를 유지하려면 아래 절차를 사용하세요.

```bash
mkdir -p /app/jasca
tar -xzf jasca-offline-manual-advisory-20260619-bundle.tar.gz
cd jasca-offline-manual-advisory-20260619
cp deploy-existing-layout.env.example deploy-existing-layout.env
vi deploy-existing-layout.env
chmod +x deploy-existing-layout.sh
./deploy-existing-layout.sh
docker logs -f jasca
```

`deploy-existing-layout.env`에서 최소한 아래 값은 운영 환경에 맞게 수정해야 합니다.

```bash
CORS_ORIGIN=https://your-jasca.example.com
JWT_SECRET=replace-with-a-long-random-secret
DB_PASSWORD=replace-with-existing-or-new-db-password
DATABASE_URL=postgresql://jasca:${DB_PASSWORD}@localhost:5432/jasca
TRIVY_CACHE_MOUNT=/root/.cache/trivy
```

기존 배포를 교체하는 경우 `DB_PASSWORD`는 기존 PostgreSQL 데이터 디렉터리와 호환되는 값이어야 합니다. 현재 서버에서 이미 사용 중인 DB 비밀번호가 있다면 같은 값을 `deploy-existing-layout.env`에 넣으세요.

v0.2.4부터는 수동 취약점 Advisory 기능을 위해 `ManualAdvisory` 테이블이 추가됩니다. 기존 데이터를 유지하려면 `/app/jasca/pgdata`, `/app/jasca/redis`를 삭제하지 말고 백업 후 그대로 마운트하세요.

이 스크립트는 내부적으로 다음과 같은 Docker 실행 구조를 사용합니다.

```bash
docker stop jasca || true
docker rm jasca || true
docker run -d \
  --name jasca \
  --restart unless-stopped \
  -p 3005:3000 \
  -e CORS_ORIGIN="$CORS_ORIGIN" \
  -e PORT=3001 \
  -e JWT_SECRET="$JWT_SECRET" \
  -e DB_PASSWORD="$DB_PASSWORD" \
  -e REDIS_URL="redis://localhost:6379" \
  -e DATABASE_URL="postgresql://jasca:${DB_PASSWORD}@localhost:5432/jasca" \
  -v /app/jasca/pgdata:/var/lib/postgresql/data \
  -v /app/jasca/redis:/var/lib/redis \
  -v /etc/hosts:/etc/hosts:ro \
  -v /root/.cache/trivy:/app/trivy-db:ro \
  jasca-offline:latest
```

Trivy 캐시 위치가 다르면 `deploy-existing-layout.env`에서 아래 값만 변경하면 됩니다.

```bash
TRIVY_CACHE_MOUNT=/app/trivy-cache
```

API 포트를 임시 진단용으로 호스트에 노출해야 한다면 아래 값을 설정하세요.

```bash
EXPOSE_API_PORT=1
```

## 기본 Linux 실행

Docker volume 기반 기본 실행을 사용할 수도 있습니다.

```bash
chmod +x start.sh
JWT_SECRET=replace-with-a-long-random-secret DB_PASSWORD=replace-with-db-password ./start.sh
```

포트를 변경하려면 다음처럼 실행합니다.

```bash
WEB_PORT=8080 API_PORT=8081 JWT_SECRET=replace-with-a-long-random-secret DB_PASSWORD=replace-with-db-password ./start.sh
```

## Windows 실행

```powershell
.\start.ps1 -JwtSecret "replace-with-a-long-random-secret" -DbPassword "replace-with-db-password"
```

포트를 변경하려면 다음처럼 실행합니다.

```powershell
.\start.ps1 -WebPort 8080 -ApiPort 8081 -JwtSecret "replace-with-a-long-random-secret" -DbPassword "replace-with-db-password"
```

## 포트

- Web: `http://localhost:3000`
- API: `http://localhost:3001`
- Swagger: `http://localhost:3001/api/docs`

기존 `/app/jasca` 배포 스크립트의 기본 웹 포트는 `3005`입니다.

## 데이터 보존

기본 실행 스크립트는 다음 Docker volume을 보존합니다.

- `jasca_postgres_data`
- `jasca_redis_data`

기존 `/app/jasca` 배포 스크립트는 다음 host-path를 보존합니다.

- `/app/jasca/pgdata`
- `/app/jasca/redis`

스크립트는 실행 중인 컨테이너만 교체하고, 데이터 디렉터리나 volume은 삭제하지 않습니다.

## 로그 확인

```bash
docker logs -f jasca
```

## 수동 실행 예시

```bash
gzip -dc jasca-offline.tar.gz | docker load
docker volume create jasca_postgres_data
docker volume create jasca_redis_data
docker run -d --name jasca --restart unless-stopped \
  -p 3000:3000 \
  -p 3001:3001 \
  -e JWT_SECRET="replace-with-a-long-random-secret" \
  -e DB_PASSWORD="replace-with-db-password" \
  -v jasca_postgres_data:/var/lib/postgresql/data \
  -v jasca_redis_data:/var/lib/redis \
  -v /root/.cache/trivy:/app/trivy-db:ro \
  jasca-offline:latest
```
