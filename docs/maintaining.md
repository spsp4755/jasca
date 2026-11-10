# JASCA 유지보수 안내

새 취약점이나 새 도구 결과를 반영해야 할 때 어디를 고치는지 먼저 고릅니다.

## 무엇을 추가하나 (판단표)

| 상황 | 하는 일 | 코드 수정 |
|---|---|---|
| 공개 DB에 없는 사내 취약점, 자체 라이브러리의 문제, 공개 DB 심각도·수정 버전이 틀려 우리 기준으로 보강 | **사내 Advisory**를 화면(보안 담당)이나 CSV로 등록 | 없음 |
| 공개 취약점이 새로 나왔는데 우리가 모름 | 인터넷 PC에서 **Trivy DB를 받아 관리 → Trivy DB로 올림**(자동 재평가) | 없음 |
| 지금 못 읽는 **도구의 결과 파일**(새 스캐너, 새 SARIF가 아닌 JSON 등) | **스캔 형식 추가**(아래) | `internal/formats/<이름>.go` + 픽스처 + 테스트 |
| 도구가 SARIF 2.1을 내보냄 | 코드 수정 없이 SARIF로 업로드 | 없음 |
| 패키지 생태계의 **버전 비교가 틀리거나 모르는 생태계**(Advisory 범위가 안 맞음, 화면에 "일반 비교" 경고) | **버전 비교 생태계 추가**(아래) | `internal/versions` + `cases.json` |
| Trivy가 새 언어·OS를 지원하게 됨 | Trivy 버전 올림(아래). 생태계 이름이 Advisory에서 쓰일 때만 버전 비교 매핑 확인 | Dockerfile (+ 필요 시 `versions.go`) |
| 새 화면, 새 API | `s.handle`로 권한과 함께 등록, 행렬 테스트에 추가(아래 "보안 규칙") | Go + `web/src` |

Advisory로 해결되는 일은 코드를 건드리지 않습니다. 코드는 "새 입력 형식"과 "새 버전 규칙"일 때만 고칩니다.

## 새 스캔 형식 추가

스캔 결과 파서는 `internal/formats` 에 있다. 새 형식 하나를 추가하는 순서는 다음과 같다.

1. **파서 파일**: `internal/formats/<이름>.go` 를 만든다. `Parser` 인터페이스(`Name`, `Detect(head []byte) bool`, `Parse(io.Reader) (*Report, error)`)를 구현한다.
   - `Detect` 는 본문 앞부분(몇 KB)만 보고 판정한다. 다른 형식과 겹치지 않는 키워드를 고른다.
   - `Parse` 는 `io.ReadAll` 로 본문 전체를 읽지 않는다. `eachKey`/`eachElem` 으로 최상위 객체를 스트리밍 디코딩하고, 닫는 토큰까지 읽어 잘린 파일이 오류가 되게 한다.
   - 심각도는 반드시 `NormalizeSeverity` 를 거치고, 결과는 `rep.add(Finding{...})` 로 넣어 지문을 계산한다. 시크릿 본문은 저장하지 않고 해시만 남긴다.
   - 이 보고서가 전부 다룬 결과 종류는 `Complete["vuln:<도구>"]` 같은 키로 표시한다(자동 해결 처리에 쓰인다). 확실하지 않으면 표시하지 않는다.
2. **등록**: 같은 파일에 `func init() { Register(<이름>Parser{}) }` 한 줄을 둔다. `Detect` 는 등록 순서대로 처음 맞는 파서를 고른다.
3. **픽스처**: `internal/formats/testdata/<이름>/` 에 실제 도구가 만든 출력을 넣는다(300KB 미만, 필요하면 `jq` 로 줄인다). 회사·내부 식별자가 들어가면 안 된다.
4. **테스트**: `formats_test.go` 의 `fixtures` 표에 파일을 추가하고(`TestDetect`, `TestParseTruncated` 가 자동으로 검사), 형식별 테스트(대상 종류, 패키지, 심각도, 지문)를 추가한 뒤 `go test ./internal/formats/...` 를 실행한다.


## 버전 비교 생태계 추가

`internal/versions`는 패키지 인벤토리의 버전이 권고(advisory)의 영향 범위에 들어가는지 판단한다.
공개 함수는 `Compare`, `Matches`, `Known` 세 개이며, 생태계 이름(소문자)으로 비교기를 고른다.

### 기존 생태계에 이름만 추가

`internal/versions/versions.go`의 `init()`에서 해당 비교기의 `reg(...)` 호출 끝에 이름을 붙인다.

```go
reg("deb", debCompare, "debian", "ubuntu", "새이름")
```

### 새 비교 방식 추가

1. `internal/versions/<이름>.go`에 `func xxxCompare(a, b string) (int, error)`를 만든다. 반환은 -1/0/1이고, 빈 문자열이나 해석할 수 없는 버전은 에러로 돌려준다(패닉 금지). 숫자 비교는 `cmpDigits`를 쓰면 오버플로가 없다.
2. `versions.go`의 `init()`에 `reg("<이름>", xxxCompare, "eco1", "eco2")`를 추가한다.
3. `internal/versions/testdata/cases.json`의 `compare`에 `[생태계, a, b, 기대값]` 형식으로 15건 이상 넣는다. 테스트가 a/b를 뒤집은 결과도 함께 검사한다. `TestCases`의 이름 목록(`deb`, `rpm`, ...)에도 새 이름을 더한다.
4. 범위 표현은 모든 생태계가 같다. 쉼표나 공백은 AND, `||`는 OR, 연산자는 `< <= > >= = == !=`, `*`는 전체이다. 범위 안의 버전도 해당 비교기로 검증되므로 잘못된 범위는 에러가 된다.

### 알아 둘 점

- `Known(eco)`가 false이면 generic 비교(숫자/알파벳 구간 비교)가 쓰인 것이다. UI는 이 경우 경고를 보여 준다. generic은 `1.0-rc1`이 `1.0`보다 크게 나오는 한계가 있다.
- rpm 비교에서 한쪽에 release가 없으면 release는 비교하지 않는다(`<1.0` 같은 범위가 `1.0-1.el8`에 맞도록).
- 현재 매핑: debian/ubuntu = deb, redhat/centos/rocky/alma/amazon/oracle/suse/photon = rpm, alpine/wolfi/chainguard = apk, npm/gomod/cargo/nuget/composer/gem = semver, pip = pep440, maven = maven.
- 테스트 실행: `go test ./internal/versions/`

## Trivy 버전 올리기

Trivy 실행 파일은 `Dockerfile`에서 공식 이미지(`aquasec/trivy:<버전>@sha256:<다이제스트>`)의 `/usr/local/bin/trivy`를 복사해 넣습니다. 다이제스트로 고정하므로 태그가 바뀌어도 이미지가 달라지지 않습니다.

1. 새 버전의 다이제스트를 확인합니다: `docker buildx imagetools inspect aquasec/trivy:<새버전>` 의 `Digest`(또는 `docker pull` 후 `docker image inspect --format '{{index .RepoDigests 0}}'`).
2. `Dockerfile`의 `COPY --from=aquasec/trivy:...@sha256:...` 줄과 `Trivy-NOTICE.txt`를 만드는 `printf` 줄의 버전 문자열을 바꿉니다.
3. 문서의 버전 표기를 바꿉니다: `DEPLOY-OFFLINE.md`(릴리스 파일 표, 서드파티 라이선스), `internal/trivy/trivy_test.go`의 주석에 적힌 버전, 필요하면 CHANGELOG.
4. 실제 Trivy로 통합 테스트를 돌립니다(아래 "테스트" 의 `JASCA_TEST_TRIVY=1`). Trivy가 CLI 플래그를 바꾸면 `internal/trivy/run.go`의 `Args`와 그 테스트가 먼저 실패합니다(예: `sbom`은 `--skip-check-update`를 받지 않음). 관리자가 고르는 스캔 옵션의 플래그는 `TestRunRealTrivyAllOptions`가 fs, image, sbom에 모두 넣어 실제 Trivy로 확인합니다.
5. Trivy DB 스키마는 Trivy 버전과 묶여 있습니다. 새 버전이 요구하는 DB(`trivy-db:2` 등)를 올려도 `metadata.json` 검사에서 통과하는지 확인하고, 필요하면 DEPLOY-OFFLINE.md의 `oras pull` 태그를 고칩니다.
6. 이미지를 빌드해 서버 스캔 한 건과 재평가 한 번을 직접 확인한 뒤 릴리스합니다.

## 테스트

```sh
# 단위 테스트만(데이터베이스 없이): DB가 필요한 테스트는 건너뜀
go vet ./... && go test ./...

# 데이터베이스 통합 테스트(권한 행렬, 업로드, 예외, 재평가 포함)
export JASCA_TEST_DATABASE_URL='postgres://jasca:<암호>@127.0.0.1:55440/jasca_test'
go test ./...

# 실제 Trivy를 쓰는 테스트(서버 스캔, DB 번들, 재평가)
JASCA_TEST_TRIVY=1 JASCA_TRIVY_BIN=/path/to/trivy JASCA_TRIVY_CACHE=/path/to/trivy-cache \
  JASCA_TEST_DATABASE_URL=... go test ./... ./internal/trivy/

# 웹(타입 검사 + 빌드). 결과는 web/dist, 이미지에 내장됨
cd web && npm ci && npm run build
```

- **`JASCA_TEST_DATABASE_URL`은 그 DB의 스키마를 지우고 다시 만듭니다.** 개발용 별도 DB를 쓰세요. 설정하지 않으면 DB 테스트는 건너뜁니다(`Dockerfile`의 `go test`도 DB 없이 돌기 때문에 건너뛰므로, DB 테스트는 릴리스 전에 따로 돌려야 합니다).
- `JASCA_TRIVY_CACHE`는 이미 받아 둔 Trivy DB 디렉터리입니다. 설정하지 않으면 해당 테스트는 건너뜁니다.
- 회사·내부 식별자 검사: `sh scripts/check-forbidden.sh`(금지어 목록은 저장소 밖 `~/.config/jasca/forbidden-words.txt`, 파일이 없거나 비어 있으면 실패).

## 릴리스

1. `deploy/jasca.yaml`의 `image: jasca:vX.Y.Z`와 `Dockerfile`의 `ARG VERSION` 기본값, `CHANGELOG.md`(새 항목을 위에 추가), `RELEASE-NOTES.md`(**이번 버전만**)를 고치고 커밋합니다. 작업 트리가 깨끗해야 합니다.
2. 개발용 PostgreSQL 컨테이너(`jasca-pg`, 기본 접속 `postgres://jasca:jasca-dev-pw@127.0.0.1:55440/jasca_release`)를 띄우고 `sh scripts/release.sh vX.Y.Z`를 실행합니다(Podman이면 `CONTAINER_ENGINE=podman`, 다른 DB는 `JASCA_TEST_DATABASE_URL`).
3. 스크립트가 하는 일: 금지어 검사 → `go vet`, `go test` → 웹 빌드 → 이미지 빌드(linux/amd64) → 이미지 안 파일 금지어 검사 → `release/`에 `jasca-vX.Y.Z.tar.gz`, `postgres-v17.11-jasca1.tar.gz`, `jasca.yaml`(이미지 태그와 머리말 버전 치환), `postgres.yaml`, `DEPLOY-OFFLINE.md`, `RELEASE-NOTES.md`, `SHA256SUMS`를 만듭니다.
4. push, 태그, `gh release create`(본문은 `RELEASE-NOTES.md`, 자산은 `release/*`)는 스크립트 밖에서 사람이 합니다.
5. 릴리스 전에 `release/jasca.yaml`을 실제 형태(kind나 테스트 클러스터)로 띄워 `/readyz`, 로그인, 스캔 업로드 한 건을 확인하세요.
6. PostgreSQL 이미지(`postgres:v17.11-jasca1`)는 `deploy/postgres.Dockerfile`로 만들며, 내용을 바꿀 때는 노드가 옛 이미지를 계속 쓰지 않도록 **태그 이름을 새로** 정하고 `scripts/release.sh`, `deploy/postgres.yaml`, DEPLOY-OFFLINE.md를 함께 고칩니다.

## 보안 규칙이 있는 곳

권한은 기능마다 조심하는 방식이 아니라 구조로 지킵니다. 새 코드는 아래를 거치기만 하면 됩니다.

| 규칙 | 위치 |
|---|---|
| 모든 라우트는 등록할 때 권한을 선언(`permPublic`, `permUser`, `permAdmin`, `permSecurity`, `permProj(역할)`, `permUpload`, `permObj(종류, 역할)`). 선언 없는 라우트는 시작할 때 panic | `server.go`의 `handle`, `access.go`의 `perm` |
| 인증 → CSRF(같은 출처 검사) → 권한 → 핸들러 순서는 `handle`이 한 곳에서 처리 | `server.go` |
| 프로젝트 안의 역할 계산(관리자=소유자, 보안 담당=최소 보기, 그 밖은 사용자·그룹·부서 멤버십 중 최고) | `access.go`의 `projectRole`, `roleFor`, `memberPathsSQL`, `memberMatchSQL` |
| 프로젝트에 매달린 **목록 조회**는 보이는 프로젝트로 제한 | `access.go`의 `visibleProjectsSQL`(그리고 결과 목록의 `visibleWhere`) |
| ID로 직접 읽는 객체는 `{id}`를 프로젝트로 풀어 `permObj`로 검사 | `registerObj`로 종류별 resolver 등록 |
| 부서가 Keycloak 그룹 경로와 겹치면 그룹 우선(부서가 그룹 권한을 만들지 못함) | `memberPathsSQL` |
| API 토큰은 `{key}` 프로젝트의 업로드 경로에서만 유효(`permUpload`) | `access.go`, `tokens.go` |

테스트가 이 규칙을 강제합니다(`server_test.go`, `matrix_test.go`).
- `TestEveryRouteDeclaresPerm`: 모든 라우트가 알려진 권한을 선언하고 `permObj`의 resolver가 등록돼 있는지.
- `TestUnauthenticatedGets401`: 공개가 아닌 모든 라우트가 로그인 없이 401인지.
- `TestPermChecks`, `TestCSRF`, `TestTokenAuth`: 권한 부족 403, 교차 출처 쓰기 거부, 토큰 동작.
- `TestCrossProjectMatrix`: 프로젝트 A의 소유자가 프로젝트 B의 키와 객체 ID를 모든 프로젝트 범위 라우트에 보내 **404**(데이터 없음)를 받는지, B의 데이터가 바뀌지 않는지. 새 라우트는 `matrixRoutes`에 사례를 추가하거나 이유와 함께 `matrixExempt`에 넣지 않으면 이 테스트가 실패합니다.

새 라우트를 만들 때는: (1) `s.handle(패턴, 권한, 핸들러)`, (2) 프로젝트에 매달린 객체면 `registerObj`와 `permObj`, (3) 목록이면 `visibleProjectsSQL`, (4) 행렬 테스트 사례 추가, (5) 쓰기면 `s.audit(...)` 호출, (6) 비밀값은 응답에 담지 않기(설정됨 여부만).
