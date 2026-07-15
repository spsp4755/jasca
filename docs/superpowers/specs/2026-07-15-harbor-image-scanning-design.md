# Harbor 이미지 직접 스캔 설계

## 목표

폐쇄망 Harbor에 있는 컨테이너 이미지를 JASCA로 업로드하지 않고 Trivy `image` 모드로 검사한다. 사용자는 수동으로 이미지와 태그 또는 Digest를 선택할 수 있고, Harbor Push Webhook은 같은 검사를 자동으로 시작한다.

## 범위

- Harbor v2 API를 사용한 프로젝트, 리포지토리, 아티팩트(Digest/태그) 조회
- 읽기 전용 Robot Account 또는 사용자명/비밀번호 기반 인증
- 수동 Harbor 이미지 Trivy 검사
- Harbor Push Artifact Webhook 수신 및 자동 Trivy 검사
- Webhook HMAC 서명 검증, 허용 프로젝트 검증, Digest 중복 실행 방지
- 관리자 설정 화면, 수동 스캔 화면, 최근 자동 실행 이력 표시

다음 항목은 이번 범위에서 제외한다.

- Checkov, Semgrep, ZAP의 Harbor 이미지 직접 검사
- Harbor 결과를 재해석하거나 Harbor 내장 취약점 스캐너 결과를 조회하는 기능
- 이미지 삭제, 태그 변경, Harbor 쓰기 권한
- 주기적 전체 레지스트리 재검사

## 구성

### Harbor 연동 설정

관리자가 Harbor Base URL, Robot Account 사용자명과 비밀값, 허용 프로젝트 목록, Webhook Secret, 자동 검사 활성화 여부를 저장한다. 비밀값은 기존 연동 설정과 동일하게 저장 후 API 및 화면에 다시 노출하지 않는다. 연결 테스트는 Harbor API의 프로젝트 조회로 DNS, TLS, 인증을 동시에 확인한다.

### 수동 검사

사용자가 새 스캔 화면에서 `Harbor 이미지`를 선택한다. JASCA는 등록된 Harbor의 프로젝트, 리포지토리, Artifact 목록을 단계적으로 조회한다. 사용자는 태그보다 Digest를 우선 선택하며, 태그만 선택한 경우 JASCA가 Harbor 응답의 Digest를 저장한다. JASCA는 `trivy image --format json <registry>/<project>/<repository>@<digest>`를 실행한다.

### Webhook 자동 검사

Harbor가 Artifact Push 이벤트를 `POST /api/harbor/webhook`으로 전송한다. Harbor의 기본 HTTP Webhook은 HMAC 서명이 아니라 설정 가능한 인증 헤더를 전달하므로, JASCA는 `Authorization: Bearer <Webhook Secret>` 값을 상수 시간으로 비교한다. JASCA는 기본 Push Artifact JSON의 `event_data.repository`와 `event_data.resources[].digest`를 검증한다. 유효한 이미지 Digest는 수동 검사와 같은 공통 Trivy 이미지 검사 경로로 전달한다. 같은 Registry, Repository, Digest가 이미 실행 중이거나 최근 완료된 경우에는 새 작업을 만들지 않는다.

## 데이터와 권한

- 설정은 전역 관리자 전용이며 Harbor 비밀값은 마스킹한다.
- 수동 검사는 기존 프로젝트 권한을 사용한다. 스캔 결과에는 Harbor URL, 리포지토리, 태그, Digest, `trigger=manual|webhook`을 증적으로 저장한다.
- Webhook 자동 검사는 관리자 설정에서 기본 JASCA 프로젝트를 지정한다. 지정되지 않았거나 비활성화된 경우 요청을 수락하지 않는다.
- Harbor 계정은 선택한 프로젝트에 대해 Artifact 조회 및 Pull만 허용한다.

## 오류 처리

- Harbor 인증 실패, TLS 오류, API 오류는 사용자에게 원인을 표시하고 자격 증명은 로그에 남기지 않는다.
- 허용되지 않은 프로젝트, 유효하지 않은 인증 헤더, 지원하지 않는 이벤트는 `401` 또는 `403`으로 거절한다.
- 이미지 Pull 또는 Trivy 실행 실패는 기존 스캔 실패 상태와 실행 증적에 기록한다.
- Webhook 중복은 성공 응답으로 무시하고 중복 사유를 감사 로그에 기록한다.

## 검증 계획

1. Harbor API 클라이언트 단위 테스트: 인증, URL 인코딩, Artifact Digest 선택, 오류 마스킹.
2. Webhook 단위 테스트: 서명 검증, Push 파싱, 허용 프로젝트 차단, Digest 중복 방지.
3. 스캔 서비스 테스트: Harbor 참조가 Trivy image 명령으로 변환되고 증적이 보존되는지 검증.
4. Docker 통합 테스트: 모의 Harbor API와 Trivy 실행을 사용해 수동 및 Webhook 스캔 완료를 확인.
5. UI 확인: 관리자 연결 테스트, 수동 선택 흐름, 자동 스캔 이력과 실패 메시지를 확인.

## 운영 전제

- JASCA에서 Harbor로 HTTPS 443 단방향 통신이 가능해야 한다.
- Harbor에서 JASCA Webhook 수신 주소로 HTTPS 통신이 가능해야 한다.
- 사내 CA를 쓰는 경우 JASCA 컨테이너에 CA 인증서를 마운트한다.
- 운영 Webhook은 JASCA의 인증된 외부 URL만 사용하고, Harbor Webhook의 `auth-header`에 `Authorization: Bearer <Webhook Secret>`을 반드시 설정한다.
