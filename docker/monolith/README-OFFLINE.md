# JASCA 폐쇄망 배포 안내

이 번들은 폐쇄망 환경에서 JASCA를 배포하기 위한 오프라인 배포 패키지입니다. Docker 이미지 아카이브, 실행 스크립트, 환경 설정 예시 파일, 배포 안내 문서를 포함합니다.

## 번들 구성

- `jasca-offline.tar.gz`: Docker 이미지 아카이브
- `start.sh`: Linux 기본 실행 스크립트
- `start.ps1`: Windows PowerShell 기본 실행 스크립트
- `deploy-existing-layout.sh`: 기존 `/app/jasca` host-path 구조용 Linux 배포 스크립트
- `deploy-existing-layout.env.example`: 운영 환경 설정 예시
- `manifest.json`: 번들 메타데이터
- `README-OFFLINE.md`: 이 문서

Docker 이미지는 PostgreSQL, Redis, JASCA API, JASCA Web, Trivy CLI, Syft CLI를 한 컨테이너 안에 포함합니다. Trivy DB는 이미지에 기본 포함하지 않습니다. 폐쇄망 서버에 이미 존재하는 Trivy 캐시를 `/app/trivy-db`로 마운트해서 사용하는 방식을 권장합니다.

JASCA의 직접 스캔은 폐쇄망 업로드 파일 분석 전용입니다. AWS, 클라우드 계정, 원격 Kubernetes 클러스터처럼 외부 API 연결이 필요한 Trivy 대상은 운영 범위에서 제외합니다.

## x86_64 서버용 이미지

배포 서버가 x86_64이면 Docker 플랫폼은 `linux/amd64`여야 합니다. 이 번들의 빌드 스크립트는 기본값을 `linux/amd64`로 고정하고, 이미지 저장 전에 실제 아키텍처를 검사합니다.

Windows PowerShell:

```powershell
.\script\build-offline-bundle.ps1
```

명시적으로 지정하려면:

```powershell
.\script\build-offline-bundle.ps1 -Platform linux/amd64
```

Linux 또는 macOS:

```bash
TARGET_PLATFORM=linux/amd64 sh ./script/build-offline-bundle.sh
```

Apple Silicon 또는 ARM 장비에서 빌드하더라도 위 설정을 사용하면 폐쇄망 x86_64 서버에서 실행 가능한 amd64 이미지를 생성합니다. 단, Docker Desktop 또는 Docker 엔진에서 amd64 에뮬레이션이 가능해야 합니다.

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

기존 운영 서버처럼 `/app/jasca/pgdata`, `/app/jasca/redis`를 host-path로 사용하고 포트 `3005`를 유지하려면 아래 절차를 사용하세요.

```bash
mkdir -p /app/jasca
cd /app/jasca
tar -xzf jasca-offline-v0.2.x-bundle.tar.gz
cd jasca-offline-v0.2.x
cp deploy-existing-layout.env.example deploy-existing-layout.env
vi deploy-existing-layout.env
chmod +x deploy-existing-layout.sh
./deploy-existing-layout.sh
docker logs -f jasca
```

`deploy-existing-layout.env`에서 최소한 아래 값을 운영 환경에 맞게 수정해야 합니다.

```bash
CORS_ORIGIN=https://your-jasca.example.com
JWT_SECRET=replace-with-a-long-random-secret
DB_PASSWORD=replace-with-existing-or-new-db-password
DATABASE_URL=postgresql://jasca:${DB_PASSWORD}@localhost:5432/jasca
TRIVY_CACHE_MOUNT=/root/.cache/trivy
TRIVY_UPLOAD_MAX_BYTES=2147483648
SYFT_BINARY_PATH=syft
TRIVY_RPM_OS_FAMILY=redhat
TRIVY_RPM_OS_VERSION=8
```

기존 배포를 교체하는 경우 `DB_PASSWORD`는 기존 PostgreSQL 데이터 디렉터리와 호환되는 값이어야 합니다. 현재 서버에서 이미 사용 중인 DB 비밀번호가 있다면 같은 값을 `deploy-existing-layout.env`에 넣으세요.

## 대용량 파일 업로드

브라우저에서 직접 Trivy 스캔 파일을 업로드할 때 큰 RPM/압축 파일을 검사해야 하면 아래 값을 늘리세요.

```bash
TRIVY_UPLOAD_MAX_BYTES=2147483648
```

사내 reverse proxy, L7, WAF를 `https://jasca...` 앞단에 두고 있다면 해당 장비의 업로드 제한도 별도로 2GB 이상으로 올려야 합니다. 예를 들어 Nginx는 `client_max_body_size`, Apache는 `LimitRequestBody` 설정을 확인합니다.

## Syft SBOM 보강 검사

JASCA는 폐쇄망에서 업로드 파일을 먼저 Trivy로 직접 검사하고, 결과가 비어 있거나 패키지 식별이 부족하면 Syft로 SBOM을 생성한 뒤 `trivy sbom`으로 재검사할 수 있습니다. 이 기능은 컨테이너 내부의 Syft 바이너리를 사용하므로 런타임 인터넷 연결이 필요하지 않습니다.

검사 화면의 `Analysis strategy`는 다음 기준으로 사용하세요.

- `폐쇄망 자동 보강`: 기본값입니다. Trivy 직접 검사 결과가 부족하면 Syft SBOM 경유 검사를 자동 수행합니다.
- `Trivy 직접 검사만`: 기존 Trivy 명령 결과만 확인하고 싶을 때 사용합니다.
- `Syft SBOM 우선`: Alloy 같은 소스/릴리즈 압축본에서 직접 검사 누락이 의심될 때 사용합니다.

## Clustara 폐쇄망 연동

관리자 화면의 `Clustara 연동`에서 제공받은 curl 값에 맞춰 Base URL, Scan API 경로, SBOM API 경로, 인증 방식(`없음`, `X-API-Key`, `Bearer`), 기본 `cluster_id`, `scanner`, `generator`를 설정할 수 있습니다. 인증 비밀값은 저장 후 화면과 API 응답에 다시 표시되지 않습니다.

Clustara HTTPS 인증서가 사내 CA로 발급됐다면 `deploy-existing-layout.env`에 호스트 인증서 파일을 지정합니다.

```bash
INTERNAL_CA_CERT=/app/jasca/certs/internal-ca.crt
```

배포 스크립트는 이 파일을 읽기 전용으로 마운트하고 컨테이너에 `NODE_EXTRA_CA_CERTS=/app/jasca-ca/internal-ca.crt`를 설정합니다. 가능하면 관리자 UI의 TLS 검증을 계속 활성화하세요.

방화벽 적용 후 컨테이너에서 먼저 확인합니다.

```bash
docker exec jasca getent hosts clustara.internal
docker exec jasca node -e "fetch('https://clustara.internal').then(r=>console.log(r.status)).catch(e=>{console.error(e.message);process.exit(1)})"
```

Clustara 장애나 방화벽 차단은 JASCA 스캔 저장을 실패시키지 않습니다. 관리자 화면의 최근 전송 이력에서 실패 사유를 확인하고 `재전송`을 실행합니다. 인증 비밀값은 JASCA PostgreSQL 설정 데이터에 저장되므로 `pgdata`와 백업 파일의 접근 권한을 제한해야 합니다.

## Standalone RPM 검사

Standalone RPM 파일을 업로드해서 스캔할 때는 취약점 DB 매칭을 위해 RPM이 어느 배포판/버전 기준인지 알아야 합니다. 업로드 화면에서 직접 입력할 수 있고, 운영 기본값은 `deploy-existing-layout.env`에서 지정할 수 있습니다.

```bash
TRIVY_RPM_OS_FAMILY=redhat
TRIVY_RPM_OS_VERSION=8
```

예시는 `redhat/8`, `redhat/9`, `rocky/9`, `alma/9`, `centos/7`처럼 운영 환경에 맞춰 지정하세요.

## 롤백

새 이미지 배포 전 기존 이미지를 태그로 남겨두면 빠르게 롤백할 수 있습니다.

```bash
docker tag jasca-offline:latest jasca-offline:rollback-before-upgrade
```

문제가 발생하면 기존 컨테이너를 내리고 롤백 태그로 다시 실행합니다.

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
  jasca-offline:rollback-before-upgrade
```
