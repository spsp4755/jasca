# JASCA

JASCA는 폐쇄망 Kubernetes에서 쓰는 취약점 관리 서비스입니다. CI와 서버 Trivy 스캔, Harbor 보고서에서 나온 결과를 프로젝트 단위로 모아 상태를 추적하고, 예외를 승인하고, 새로 알려진 취약점을 다시 스캔하지 않고 반영합니다. v1.0.0은 이전 버전(v0.3.x, NestJS/Next.js)을 Go 단일 바이너리와 내장 React 웹으로 다시 만든 것입니다.

## 주요 기능

- **결과 수집**: Trivy JSON(취약점·설정 오류·비밀값), SARIF 2.1(Semgrep, Checkov 등), Harbor 취약점 보고서, CycloneDX JSON SBOM을 업로드 API로 받습니다.
- **서버 스캔**: 압축 파일(zip, tar, tar.gz/tgz)이나 `docker save` 이미지 tar를 올리면 서버의 Trivy가 검사합니다.
- **새 취약점 반영**: 관리자가 오프라인 Trivy DB를 올리면 저장된 모든 대상의 패키지 목록을 자동으로 다시 평가합니다. 공개 DB에 없는 취약점은 **사내 Advisory**(화면 또는 CSV)로 등록하면 기존 결과에도 즉시 적용됩니다.
- **결과 추적**: 대상별로 안정적인 결과 하나를 유지하고(열림, 해결됨, 위험 수용, 오탐), 사라진 결과는 자동으로 해결됨 처리하며, 다시 나타나면 재발로 표시합니다.
- **정책 게이트**: 프로젝트별 통과 기준을 업로드 응답에 담아 돌려줍니다. 판정 중 오류가 나면 실패로 처리합니다.
- **예외**: 요청, 보안 담당 승인, 만료일(최대 1년), 만료 7일 전 알림, 만료 시 자동 재오픈.
- **접근 제어**: 기본 거부. 프로젝트 멤버십(소유자, 멤버, 보기 전용)을 사용자 또는 Keycloak 그룹·부서 경로로 지정합니다.
- **Keycloak SSO**: OIDC, 부서·그룹 동기화, 구형 Keycloak(`/auth` 경로) 지원. 비상용 로컬 `admin` 한 계정만 따로 둡니다.
- **연동**: Harbor 웹훅, Mattermost·메일 알림, 사내 OpenAI 호환 LLM으로 조치 안내와 프로젝트 보고서(AI).
- **감사 로그**: 모든 쓰기를 행위자·IP와 함께 기록합니다.

## 구조

- Go 단일 바이너리(`net/http`, `pgx`)가 API와 내장 React 웹(Vite, TypeScript)을 함께 제공합니다.
- 데이터는 PostgreSQL 17에 저장하고 스키마는 시작할 때 `migrations/`의 SQL로 자동 적용합니다.
- 이미지는 `FROM scratch`, 일반 사용자(10001), 읽기 전용 루트 파일 시스템이며 Trivy 실행 파일을 포함합니다.
- 스캔 큐, 재평가, 알림 전송, 예외 만료는 프로세스 안 작업자가 DB 상태를 보며 처리합니다. 그래서 **replicas는 1**입니다.
- Trivy 취약점 DB와 스캔 작업 폴더는 PVC `jasca-data`(`/data`)에 둡니다. DB는 서버가 내려받지 않고 관리자가 올립니다.

## 빠른 시작 (Kubernetes, 폐쇄망)

릴리스 파일(`jasca-vX.Y.Z.tar.gz`, `jasca.yaml`, `postgres.yaml`)을 반입하고 다음 순서로 설치합니다. 전체 절차(이미지 반입, Keycloak 설정, Trivy DB 올리기, 업그레이드, 백업)는 **[DEPLOY-OFFLINE.md](DEPLOY-OFFLINE.md)** 를 보세요.

```sh
kubectl create namespace jasca
# jasca.yaml: JASCA_BOOTSTRAP_PASSWORD, Ingress host / postgres.yaml: POSTGRES_PASSWORD 변경
kubectl -n jasca apply -f postgres.yaml
kubectl -n jasca apply -f jasca.yaml
```

접속해 `admin`으로 로그인한 뒤(`/login?local=1`) **관리 → Trivy DB**에서 DB를 올립니다.

## CI에서 업로드

프로젝트 **설정 → API 토큰**에서 `upload` 권한 토큰(`jsc_...`)을 만들어 CI 비밀 변수 `JASCA_TOKEN`에 넣습니다. 프로젝트 **설정 → CI 연동**에서 복사용 명령을 만들 수도 있습니다.

```sh
trivy image --format json --scanners vuln,secret -o trivy.json "$IMAGE:$TAG"
curl -fsS -X POST -H "Authorization: Bearer $JASCA_TOKEN" --data-binary @trivy.json \
  "https://jasca.example.internal/api/v1/projects/<프로젝트 키>/scans?target=$IMAGE&kind=image&ref=$TAG&scanners=vuln,secret" \
  | tee jasca.json
grep -q '"passed":true' jasca.json   # 정책을 통과하지 못하면 종료 코드 1
```

- gzip으로 보내려면 `gzip -c trivy.json | curl ... -H "Content-Encoding: gzip" --data-binary @- "<주소>"`.
- 쿼리: `target`(대상 이름), `kind`(`image`, `repo`, `fs`, `sbom`), `ref`(태그나 커밋), `format`(자동 감지를 건너뜀), `scanners`(`vuln`, `misconfig`, `secret`).
- `scanners`는 이 보고서가 그 종류를 **끝까지 검사했다**는 표시입니다. Trivy JSON은 결과가 들어 있는 종류만 완전한 것으로 보므로, 결과가 0건이어도 이전에 열려 있던 결과를 해결됨으로 바꾸려면 실제로 돌린 스캐너를 적으세요. 돌리지 않은 스캐너는 적지 마세요(그 종류의 열린 결과가 잘못 해결됨 처리됩니다).
- 응답: `{"scan_id", "target_id", "summary", "policy":{"passed","reasons"}, "duplicate"}`. 같은 보고서를 10분 안에 다시 올리면 기존 스캔을 돌려줍니다(`duplicate: true`).

## 문서

- [DEPLOY-OFFLINE.md](DEPLOY-OFFLINE.md): 설치, Keycloak, Trivy DB, Harbor, 업그레이드, 백업
- [docs/admin-guide.md](docs/admin-guide.md): 관리 화면 안내
- [docs/user-guide.md](docs/user-guide.md): 사용자 안내
- [docs/maintaining.md](docs/maintaining.md): 유지보수(형식, 버전 비교, Advisory, 테스트, 릴리스)
- [CHANGELOG.md](CHANGELOG.md), [RELEASE-NOTES.md](RELEASE-NOTES.md)

## 라이선스

MIT. 이미지에 들어 있는 서드파티(Trivy 등)의 라이선스는 이미지의 `/licenses/`에 있습니다.
