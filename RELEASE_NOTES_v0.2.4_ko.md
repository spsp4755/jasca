# JASCA v0.2.4 변경사항

## 주요 변경

- 관리자 메뉴에 `수동 취약점 Advisory` 화면을 추가했습니다.
- Admin에서 CVE ID, 패키지명, 영향 버전 범위, 심각도, 수정 버전, 조치 가이드, 참고 URL을 등록/수정/삭제할 수 있습니다.
- Trivy JSON 저장 시 등록된 수동 Advisory를 패키지/버전 기준으로 매칭해 일반 취약점처럼 결과에 포함합니다.
- Trivy DB에 아직 없는 사내 긴급 취약점도 JASCA에서 먼저 운영 반영할 수 있습니다.
- 검사 대상 파일 직접 업로드 기능이 `.zip`, `.tar`, `.tar.gz`, `.tgz` 압축 파일을 지원합니다.
- 폐쇄망 Trivy 실행 옵션을 UI에서 선택할 수 있습니다: offline scan, DB update skip, Java DB update skip, ignore unfixed, scanner, severity, timeout.
- Trivy 직접 검사 중 `검사 중지`를 실행할 수 있도록 취소 API와 UI 버튼을 추가했습니다.
- Docker 이미지에 압축 해제용 `unzip`을 포함했습니다.

## DB 변경

- `ManualAdvisory` 테이블이 추가됩니다.
- 배포 시 컨테이너 entrypoint의 Prisma migration 단계에서 자동 적용됩니다.
- 기존 `/app/jasca/pgdata`, `/app/jasca/redis`는 삭제하지 말고 백업 후 그대로 사용해야 합니다.

## 검증 결과

- `docker build -f docker/monolith/Dockerfile -t jasca-offline:latest .` 성공
- 최신 이미지로 로컬 preview 컨테이너 기동 성공
- `/admin/manual-advisories` HTTP 200 확인
- `/dashboard/scans/new` HTTP 200 확인
- 수동 Advisory 등록 후 Trivy JSON 업로드 시 `left-pad 1.3.0`이 `MANUAL-KCB-SMOKE-*` 취약점으로 생성되는 것 확인
- 생성 취약점은 `HIGH`, `fixedVersion=2.0.0`, `layer.source=manual-advisory`로 저장됨

## 폐쇄망 반입 후 배포 요약

```bash
mkdir -p /app/jasca
cd /app/jasca
tar -czf pgdata-backup-before-v024-$(date +%Y%m%d-%H%M%S).tar.gz pgdata
tar -czf redis-backup-before-v024-$(date +%Y%m%d-%H%M%S).tar.gz redis

tar -xzf jasca-offline-manual-advisory-20260619-bundle.tar.gz
cd jasca-offline-manual-advisory-20260619
cp deploy-existing-layout.env.example deploy-existing-layout.env
vi deploy-existing-layout.env
chmod +x deploy-existing-layout.sh
./deploy-existing-layout.sh
docker logs -f jasca
```

운영 서버의 기존 설정 기준 최소 값:

```bash
APP_DIR=/app/jasca
IMAGE_NAME=jasca-offline:latest
CONTAINER_NAME=jasca
WEB_PORT=3005
CORS_ORIGIN=https://jasca.koreacb.com
JWT_SECRET=jasca_offline_secret
DB_PASSWORD=jasca_secret
DATABASE_URL=postgresql://jasca:${DB_PASSWORD}@localhost:5432/jasca
REDIS_URL=redis://localhost:6379
TRIVY_CACHE_MOUNT=/root/.cache/trivy
HOSTS_MOUNT=/etc/hosts
```

`TRIVY_CACHE_MOUNT`는 실제 폐쇄망 서버의 Trivy cache 경로에 맞게 수정하세요. 컨테이너는 호스트 Trivy 바이너리를 직접 실행하지 않고, 이미지 안의 Trivy CLI와 마운트된 Trivy DB/cache를 사용합니다.

## 롤백 요약

오류가 발생하면 새 컨테이너만 내리고 기존 이미지 태그로 다시 실행하면 됩니다. 데이터가 손상되었거나 migration 이후 되돌려야 하는 경우에는 위에서 만든 `pgdata`, `redis` 백업 tar.gz를 복원한 뒤 기존 이미지로 기동하세요.
