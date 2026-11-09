# JASCA v1.0.0

이전 버전(v0.3.x)을 Go 단일 바이너리 + 내장 React 웹으로 다시 만든 릴리스입니다. **기존 데이터는 옮기지 않으며 새로 설치합니다.**

## 주요 내용

- 가볍고 안전한 구조: 이미지 `FROM scratch`, 일반 사용자 실행, 읽기 전용 루트 파일 시스템. PostgreSQL 17 하나만 필요합니다(Redis와 내장 DB 없음).
- Keycloak SSO(OIDC + PKCE)와 부서·그룹 기반 프로젝트 멤버 지정. 비상용 로컬 `admin` 한 계정(`/login?local=1`).
- 기본 거부 권한 구조: 모든 라우트가 권한을 선언하고, 프로젝트 접근은 한 곳에서 판정하며, 전수 권한 테스트와 프로젝트 간 접근 차단 테스트를 통과해야 릴리스합니다.
- 새 취약점을 다시 스캔하지 않고 반영: Trivy DB 번들을 올리면 모든 대상의 패키지 목록을 자동 재평가하고, 사내 Advisory는 저장 즉시 기존 결과에 적용됩니다.
- 서버 Trivy 스캔(압축 파일, 이미지 tar), Harbor 웹훅 연동, AI 보고서와 CVE 조치 안내.
- 정책 게이트, 예외 승인 흐름, Mattermost·메일 알림, 감사 로그.
- 업로드 형식: Trivy JSON, SARIF 2.1, Harbor 취약점 보고서, CycloneDX JSON.

## v0.3.x에서 바뀐 점 (호환되지 않음)

- **API 경로가 모두 새로 바뀌었습니다.** CI 업로드는 `POST /api/v1/projects/{프로젝트 키}/scans`(쿼리: `target`, `kind`, `ref`, `format`, `scanners`)이며, `Authorization: Bearer <토큰>`으로 인증합니다. 이전의 `/api/scans/upload/file`, `/api/policies/verdict` 같은 경로는 없습니다.
- **토큰 형식이 바뀌었습니다.** `jsc_`로 시작하고 프로젝트 하나에만 묶이며, 권한 범위(`upload`, `read`)와 만료일(최대 1년)이 필수입니다. 이전의 `jasca_` 토큰은 쓸 수 없으므로 CI의 비밀 변수를 새 토큰으로 바꾸세요.
- **정책 판정은 업로드 응답에 담깁니다**(`policy.passed`). 별도 verdict 호출이 필요 없습니다. CI는 응답의 `"passed":true`를 확인하면 됩니다.
- **조직 계층이 없어지고 프로젝트 멤버십으로 바뀌었습니다.** 시스템 역할은 `admin`, `security`, 일반 사용자뿐입니다.
- **데이터 이전이 없습니다.** 이전 DB의 사용자, 프로젝트, 스캔, 취약점 상태는 옮겨지지 않습니다. 필요하면 이전 버전을 읽기 전용으로 잠시 두세요.
- **제거된 기능**: ZAP(DAST) 실행, Semgrep·Checkov 서버 실행(SARIF 업로드로 대체), 레지스트리 pull 스캔, Harbor SBOM 연동, LDAP, 자체 MFA, 비밀번호 정책 화면, 로컬 사용자 추가, 라이선스 정책, 스키마·API 탐색기, DB 관리 화면, 여러 replica.
- **Trivy DB는 이미지에 없습니다.** 설치 뒤 인터넷 PC에서 받아 **관리 → Trivy DB**에서 올려야 서버 스캔과 재평가가 동작합니다.

## 업그레이드 안내

v0.3.x에서의 업그레이드는 지원하지 않습니다. **새 Namespace에 새로 설치**하고 `DEPLOY-OFFLINE.md`를 따르세요. 같은 Namespace에 설치하면 이전 PVC와 Secret을 재사용하지 말고 새 값으로 만드세요. v1.0.0 이후 버전은 이미지 태그만 바꿔 올립니다(DB 스키마는 시작할 때 자동 적용).

## 설치 전 확인

- `jasca.yaml`의 `JASCA_BOOTSTRAP_PASSWORD`(12~72자), `postgres.yaml`의 `POSTGRES_PASSWORD`, Ingress 주소를 바꿨는지.
- Ingress의 `proxy-body-size`(기본 2g)와 600초 제한 시간.
- replicas는 1로 유지합니다.
