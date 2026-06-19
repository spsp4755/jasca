# JASCA

JASCA는 Trivy 스캔 결과를 수집하고, 조직/프로젝트/정책 기준으로 취약점을 관리하기 위한 보안 취약점 관리 시스템입니다.

## 주요 기능

- Trivy JSON 결과 업로드 및 취약점 조회
- 검사 대상 파일 직접 업로드 후 Trivy 스캔
- `.zip`, `.tar`, `.tar.gz`, `.tgz` 압축 파일 업로드 후 Trivy 스캔
- 관리자 수동 Advisory 등록 및 Trivy 결과 보강
- 조직, 프로젝트, 사용자 역할 기반 접근 제어
- 정책 등록, 정책 평가, 정책 위반 결과 확인
- 취약점 심각도/상태별 대시보드와 통계
- 폐쇄망 배포를 위한 Docker 오프라인 번들 지원

## 폐쇄망 배포

GitHub Release에서 오프라인 번들을 내려받아 폐쇄망 서버로 반입할 수 있습니다.

- 최신 배포 번들: `jasca-offline-manual-advisory-20260619-bundle.tar.gz`
- 체크섬 파일: `jasca-offline-manual-advisory-20260619-SHA256SUMS.txt`
- Release: https://github.com/spsp4755/jasca/releases

폐쇄망 서버에서 기본 배포 절차는 다음과 같습니다.

```bash
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
TRIVY_CACHE_MOUNT=/root/.cache/trivy
```

기존 운영 서버가 `/app/jasca/pgdata`, `/app/jasca/redis`, 웹 포트 `3005` 구조를 사용한다면 기본값을 그대로 사용할 수 있습니다. 단, 기존 DB를 유지하려면 `DB_PASSWORD`는 현재 PostgreSQL 데이터와 호환되는 값으로 설정해야 합니다.

새 버전은 최초 기동 시 Prisma migration으로 `ManualAdvisory` 테이블을 추가합니다. 기존 `pgdata`와 `redis` 디렉터리는 삭제하지 말고 백업 후 그대로 마운트해서 사용하세요.

## 문서

전체 문서는 `docs` 디렉터리에서 확인할 수 있습니다.

### 사용자 가이드

- [대시보드](docs/User_Dashboard_kr.md)
- [프로젝트](docs/User_Projects_kr.md)
- [스캔 결과](docs/User_ScanResults_kr.md)
- [취약점](docs/User_Vulnerabilities_kr.md)
- [정책](docs/User_Policies_kr.md)
- [리포트](docs/User_Reports_kr.md)
- [알림](docs/User_Notifications_kr.md)
- [설정](docs/User_Settings_kr.md)

### 관리자 가이드

- [관리자 대시보드](docs/Admin_Dashboard_kr.md)
- [조직 관리](docs/Admin_Organizations_kr.md)
- [사용자 관리](docs/Admin_Users_kr.md)
- [프로젝트 관리](docs/Admin_Projects_kr.md)
- [정책 관리](docs/Admin_Policies_kr.md)
- [예외 승인](docs/Admin_Exceptions_kr.md)
- [시스템 설정](docs/Admin_TrivySettings_kr.md)

### 매뉴얼

- [통합 사용자 매뉴얼](docs/User_Manual_kr.md)
