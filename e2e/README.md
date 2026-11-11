# 브라우저 테스트 (E2E)

실제 Keycloak에 로그인해서 화면을 끝까지 눌러 보는 테스트입니다. 개발 PC에서만 돌리며 배포 이미지에는 들어가지 않습니다.
Trivy 보고서 업로드, MCP 조회, 예외 승인, Advisory 재평가, 서버 스캔, Trivy DB 교체, 비밀값 누출, 접근성(axe)을 함께 확인합니다.

## 준비물

- PostgreSQL 컨테이너 (실행할 때마다 `JASCA_E2E_PG_DB`의 `public` 스키마를 지웁니다. 이름에 `e2e`가 없으면 거부합니다. DB는 미리 만들어 둡니다: `CREATE DATABASE jasca_e2e`)
- 개발용 Keycloak(`start-dev`) 컨테이너. `keycloak-setup.sh`가 realm `jasca`, client `jasca`(confidential, redirect `http://localhost:18301/*`, `department` 매퍼(Multivalued)와 groups 매퍼(Full path), 클라이언트 역할 `jasca-admin`·`jasca-security`), 서비스 client `jasca-sync`(`view-users`, `query-groups`), 사용자 `kim`(부서 `보안실/취약점팀`, `jasca-security`)·`lee`(`개발본부/플랫폼팀`)·`park`(부서 없음)을 만들거나 맞춥니다. 여러 번 돌려도 안전합니다.
- Node.js 22+, Go, `playwright-core`와 Chromium. axe-core는 `e2e/package.json`의 devDependency로 받습니다(`run.sh`가 필요하면 `npm install`). CDN은 쓰지 않습니다.
- 스캔·Trivy DB 스위트용: docker. 바이너리는 `aquasec/trivy` 이미지에서, DB는 도커 볼륨(`JASCA_E2E_TRIVY_VOLUME`)에서 `e2e/.out/keep`으로 꺼냅니다(처음 한 번, 1.6GB). docker가 없거나 꺼내지 못하면 두 스위트는 건너뜁니다.

## 실행

```sh
cp e2e/.env.example e2e/.env   # 값을 채웁니다 (git에 올라가지 않음)
sh e2e/run.sh                  # 빌드 → Trivy 준비 → DB 초기화 → Keycloak 설정 → 서버 시작 → 전체 스위트
sh e2e/run.sh login admin      # 일부만 (빈 DB에서는 login이 먼저 SSO 설정을 해 두어야 합니다)
```

결과 로그(`<스위트>.log`)와 스크린샷, 서버 로그는 `e2e/.out/`에 남습니다(`.out/keep`만 다음 실행에 재사용). 하나라도 실패하면 종료 코드가 0이 아닙니다.

`.env`에서 PC마다 다른 값을 바꿉니다: `JASCA_E2E_PLAYWRIGHT`(playwright-core 경로), `JASCA_E2E_CHROME`(Chromium 실행 파일), `JASCA_E2E_LD_LIBRARY_PATH`(Chromium 공유 라이브러리), 컨테이너 이름, 포트, 비밀번호. 서버 포트는 기본 18301이고 Keycloak redirect(`JASCA_E2E_KC_REDIRECT_BASES`)에도 들어 있어야 합니다.

## 순서와 내용

`login`이 관리자 화면으로 SSO·동기화를 설정하므로 항상 처음입니다. `projects`가 만든 토큰을 `ingest`가 쓰고, `ingest`가 올린 결과를 `mcp`가 조회합니다. 나머지는 스위트마다 자기 프로젝트(키가 다름)를 만들어 서로 간섭하지 않습니다.

| 파일 | 확인하는 것 |
|---|---|
| login.cjs | 로컬 관리자 로그인(잘못된 비밀번호 포함), 관리 화면에서 SSO·동기화 설정과 지금 동기화, kim/lee/park의 실제 Keycloak 로그인과 역할 매핑, 관리 → 사용자와 동기화 화면에 부서 표시, 역할 변경 확인 창과 "Keycloak 역할 따름"으로 되돌리기, 로컬 admin 잠금, 로그아웃. 세션이 끝난 뒤 로그인 화면의 안내와 원래 주소(#위치 포함)로 복귀, 비밀번호 5회 실패 뒤 남은 잠금 시간 안내 |
| projects.cjs | 프로젝트 만들기, 부서(`/개발본부`)로 멤버 추가 후 lee만 접근, API 토큰은 만들 때 한 번만 보임(닫은 뒤·새로고침 뒤·목록 API에 없음). 창을 열면 첫 입력 칸에 포커스(Enter로 닫히지 않음, Esc 뒤 연 버튼으로 복귀), 저장 두 번 눌러도 요청 1건, 고른 만료일이 서버 표시 시간대의 그 날짜 |
| ingest.cjs | `internal/formats/testdata`의 보고서를 토큰으로 업로드(curl과 같은 방식, gzip 포함): 잘못된 토큰 401, 중복 업로드, 치명 결과가 있으면 `passed:false`, 다섯 가지 형식, 쓰레기 본문 400, 결과가 API와 화면에 보임. 스캐너를 줄인 스캔의 비교 수치(검사하지 않은 종류는 사라짐·새로 발견에 넣지 않음), 정책을 끈 프로젝트의 "정책 사용 안 함", 보고서 인쇄 폭(A4, `shots/report-a4.pdf`) |
| mcp.cjs | 프로젝트 설정의 MCP 연동 칸(주소, 설정 예시, 도구 목록이 서버와 같음), 읽기 토큰으로 실제 HTTP 호출: 토큰 없음 401·업로드 토큰 403·GET 405, `initialize` → `tools/list` → `tools/call`(2025-11-25), `server/discover`와 `tools/call`(2026-07-28), 모르는 규격 버전 거부, 토큰의 마지막 사용 기록 |
| exceptions.cjs | lee가 결과 창에서 예외 요청, lee는 승인 못 함(버튼 없음, API 403), 요청한 결과의 세부 정보에 "예외 승인 대기 중", kim이 승인 화면에서 승인(1024px 창에서도 버튼이 보임), 결과가 열림이 아님, kim도 자기 요청은 승인·반려 못 함, 권한 없는 park과 보기 전용 park에게 보이는 것, 멤버가 아닌 보안 담당의 전사 범위 요청 |
| advisory.cjs | 화면에서 사내 Advisory를 만들면(영향 미리보기 포함, 저장 두 번 눌러도 1건) 이미 올라간 패키지에 재스캔 없이 결과가 생김. 잘못된 ID 안내, 없는 Advisory는 찾을 수 없음만 표시 |
| scan.cjs | 작은 tar.gz를 올려 서버의 실제 Trivy로 검사, 완료와 결과 확인 |
| trivydb.cjs | 잘못된 DB 번들은 한국어 메시지로 거부되고 기존 DB 유지, 취약점 DB 칸에서 고른 Java DB도 Java DB로 적용되고 그렇게 안내됨(재평가 없음), 올바른 번들은 적용되고 재평가 실행이 끝남, 스캔 옵션 저장과 서버 검증 메시지 |
| admin.cjs | SSO·동기화·Harbor 로봇·SMTP·AI 비밀값을 넣고 모든 관리 API와 화면을 훑으며 모든 JSON 응답과 서버 로그에 그 값이 없는지 검사. 감사 로그가 스캔 옵션·로그인 실패 사유·대상 종류를 화면의 말로 보여 줌 |
| due.cjs | 새 결과에 기본 조치 기한이 붙음, 관리 → 기본 정책에서 심각도별 기한 저장(잘못된 값 거부, 확인 창, 바뀐 건수 안내), lee가 결과 창에서 "나에게"·지난 날짜 기한·정책 기한으로 되돌리기, 목록의 "N일 남음/지남"과 담당자·기한 필터·기한 순 정렬(1024px 포함), 프로젝트와 홈의 기한 지남·내 담당 수와 링크, CSV·MCP, 여러 건 담당자 지정, 보기 전용 park은 읽기만(API 403), 알림 이벤트 두 가지와 감사 로그 표시 |
| a11y.cjs | 로그인·홈·프로젝트(탭 전부)·취약점·스캔·예외·Advisory·보고서·관리 화면 전체를 라이트·다크로 axe(wcag2a, wcag2aa): serious/critical 위반 0건 |
| console.cjs | 세 사용자의 화면 순회 뒤, 모든 스위트가 기록한 페이지·콘솔 오류가 없음. 예외는 `lib.cjs`의 `CONSOLE_ALLOW`에 이유와 함께 적힌 것뿐 |

`console`은 앞선 스위트들이 남긴 `.out/net.log`, `.out/console-errors.log`를 검사하므로 마지막에 돌립니다.
