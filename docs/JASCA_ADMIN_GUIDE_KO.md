# JASCA 관리자 가이드

이 문서는 JASCA 관리자가 시스템을 구성하고 운영하는 데 필요한 모든 관리자 기능을 설명합니다. 조직, 사용자, 권한, 프로젝트, 정책, 예외, 워크플로우, 컴플라이언스, AI, Trivy, 알림, CI/CD, 감사, DB, 스키마, API Explorer, 폐쇄망 배포 운영까지 포함합니다.

## 1. 관리자 역할과 책임

### 1.1 관리자 역할

| 역할 | 설명 | 주요 책임 |
| --- | --- | --- |
| SYSTEM_ADMIN | 시스템 전체 관리자 | 전체 조직과 시스템 설정, DB, 감사, AI, Trivy, SSO 관리 |
| ORG_ADMIN | 조직 관리자 | 소속 조직의 사용자, 프로젝트, 정책, 예외, 토큰 관리 |
| SECURITY_ADMIN | 보안 관리자 | 취약점, 정책, 예외, Trivy, 수동 취약점, 컴플라이언스 관리 |
| PROJECT_ADMIN | 프로젝트 관리자 | 프로젝트 단위 취약점 처리, 정책 예외, 담당자 관리 |
| DEVELOPER | 개발자 | 스캔 업로드, 취약점 조치 |
| VIEWER | 조회 사용자 | 읽기 전용 조회 |

### 1.2 권한 범위

JASCA는 조직과 프로젝트 단위로 접근 범위를 나눕니다.

| 범위 | 의미 |
| --- | --- |
| GLOBAL 또는 SYSTEM | 시스템 전체 범위 |
| ORGANIZATION | 특정 조직 범위 |
| PROJECT | 특정 프로젝트 범위 |

SYSTEM_ADMIN은 모든 범위에 접근할 수 있습니다. ORG_ADMIN은 조직 범위, PROJECT_ADMIN은 프로젝트 범위를 중심으로 관리합니다.

## 2. 관리자 콘솔 접속

### 2.1 접속

관리자 권한이 있는 계정으로 로그인한 뒤 우측 상단 또는 사이드 메뉴의 `관리자`로 이동합니다.

관리자 경로:

```text
/admin
```

### 2.2 관리자 메뉴 전체 목록

| 메뉴 | 경로 | 설명 |
| --- | --- | --- |
| 관리자 대시보드 | `/admin` | 시스템 전체 현황 요약 |
| 조직 관리 | `/admin/organizations` | 조직 생성, 수정, 삭제, 조직별 설정 |
| 사용자 관리 | `/admin/users` | 사용자 계정, 역할, 상태 관리 |
| 권한 관리 | `/admin/permissions` | RBAC 역할과 권한 구조 확인/관리 |
| 프로젝트 관리 | `/admin/projects` | 전체 프로젝트 조회, 생성, 수정, 삭제 |
| 보안 정책 | `/admin/policies` | 정책 생성, 수정, 삭제, 규칙 관리 |
| 예외 관리 | `/admin/exceptions` | 정책/취약점 예외 요청 검토 |
| 워크플로우 | `/admin/workflows` | 취약점 처리 흐름과 자동화 관리 |
| 컴플라이언스 | `/admin/compliance` | 조직별 규정 준수 현황 |
| 취약점 관리 | `/admin/vulnerabilities` | 전체 취약점 관리와 필터링 |
| 라이선스 관리 | `/admin/licenses` | 라이선스 카탈로그, 추적, 프로젝트별 라이선스 |
| 수동 취약점 | `/admin/manual-advisories` | 외부에서 확보한 취약점 정보를 수동 등록 |
| AI 설정 | `/admin/ai-settings` | AI 모델 공급자, URL, 모델명, 키 설정 |
| AI 프롬프트 관리 | `/admin/ai-prompts` | AI 분석 프롬프트 수정 |
| AI 실행 이력 | `/admin/ai-history` | AI 호출 이력, 성공/실패, 비용/토큰 확인 |
| Trivy 설정 | `/admin/trivy-settings` | Trivy 기본 옵션과 cache dir 설정 |
| 알림 설정 | `/admin/notification-settings` | 알림 채널과 규칙 관리 |
| CI/CD 연동 | `/admin/ci-integration` | CI/CD 업로드 연동 설정과 예시 |
| API 토큰 | `/admin/api-tokens` | 관리자 관점의 API 토큰 관리 |
| API Explorer | `/admin/api-explorer` | API 엔드포인트 테스트/탐색 |
| SSO 설정 | `/admin/sso-settings` | SSO, Keycloak, LDAP 설정 |
| 감사 로그 | `/admin/audit-logs` | 시스템 행위와 변경 이력 조회 |
| 데이터베이스 | `/admin/database` | DB 상태와 테이블 현황 확인 |
| 스키마 | `/admin/schema` | Prisma/ERD 기반 데이터 구조 확인 |
| 관리자 사이트맵 | `/admin/sitemap` | 관리자 메뉴 전체 구조 |

## 3. 관리자 대시보드

관리자 대시보드는 시스템 전체 운영 현황을 빠르게 확인하는 화면입니다.

확인 항목:

- 전체 조직 수
- 전체 사용자 수
- 전체 프로젝트 수
- 전체 취약점 수
- 심각도별 취약점 수
- 최근 스캔 현황
- 정책 위반 현황
- 최근 관리자 작업

운영자는 매일 다음 항목을 우선 확인하는 것을 권장합니다.

- Critical/High 증가 여부
- 실패한 스캔 또는 업로드 오류
- Trivy DB 상태
- 예외 요청 대기 건수
- AI 연결 실패 여부

## 4. 조직 관리

조직은 사용자와 프로젝트를 분리하는 최상위 운영 단위입니다.

### 4.1 조직 목록

확인 항목:

- 조직명
- 설명
- 사용자 수
- 프로젝트 수
- 생성일
- 상태

### 4.2 조직 생성

1. `조직 관리`로 이동합니다.
2. `조직 추가`를 클릭합니다.
3. 조직명과 설명을 입력합니다.
4. 저장합니다.

### 4.3 조직 수정

1. 조직 목록에서 수정할 조직을 선택합니다.
2. 이름 또는 설명을 변경합니다.
3. 저장합니다.

### 4.4 조직 삭제

조직 삭제는 사용자, 프로젝트, 스캔 데이터에 영향을 줄 수 있습니다. 운영 환경에서는 삭제보다 비활성화 또는 권한 제거를 우선 검토합니다.

삭제 전 확인:

- 소속 프로젝트 백업 여부
- 사용자 이전 여부
- 정책/예외/토큰 영향
- 감사 로그 보존 필요 여부

## 5. 사용자 관리

사용자 관리는 계정, 역할, 조직, 상태를 관리하는 기능입니다.

### 5.1 사용자 목록

확인 항목:

- 이름
- 이메일
- 소속 조직
- 역할
- 계정 상태
- 마지막 로그인
- 생성일

### 5.2 사용자 생성

1. `사용자 관리`로 이동합니다.
2. `사용자 추가`를 클릭합니다.
3. 이름, 이메일, 조직, 역할을 입력합니다.
4. 임시 비밀번호 또는 초대 방식을 선택합니다.
5. 저장합니다.

### 5.3 사용자 수정

수정 가능 항목:

- 이름
- 이메일
- 조직
- 역할
- 활성화 여부

### 5.4 사용자 비활성화

퇴사자나 장기 미사용 계정은 삭제보다 비활성화를 권장합니다.

비활성화 후 확인:

- API 토큰 삭제
- 담당 취약점 재배정
- 세션 만료
- 조직 역할 제거

### 5.5 초대 기반 가입

관리자는 사용자를 초대할 수 있습니다.

초대 시 지정:

- 이메일
- 조직
- 역할
- 만료일

사용자는 초대 코드 또는 초대 링크로 가입합니다.

## 6. 권한 관리

권한 관리는 JASCA의 RBAC 모델을 이해하고 운영하는 메뉴입니다.

### 6.1 역할별 기본 권한

| 역할 | 조회 | 스캔 업로드 | 취약점 변경 | 정책 관리 | 사용자 관리 | 시스템 설정 |
| --- | --- | --- | --- | --- | --- | --- |
| SYSTEM_ADMIN | 전체 | 가능 | 가능 | 가능 | 가능 | 가능 |
| ORG_ADMIN | 조직 범위 | 가능 | 가능 | 가능 | 가능 | 일부 |
| SECURITY_ADMIN | 접근 범위 | 가능 | 가능 | 가능 | 제한 | 보안 설정 |
| PROJECT_ADMIN | 프로젝트 범위 | 가능 | 가능 | 일부 | 불가 | 불가 |
| DEVELOPER | 접근 프로젝트 | 가능 | 제한 | 조회 | 불가 | 불가 |
| VIEWER | 접근 프로젝트 | 불가 | 불가 | 조회 | 불가 | 불가 |

### 6.2 API 토큰 권한 매핑

| API 권한 | 설명 |
| --- | --- |
| scans:read, scan:read | 스캔 조회 |
| scans:write, scan:upload | 스캔 업로드 |
| projects:read, project:read | 프로젝트 조회 |
| projects:write, project:write | 프로젝트 생성/수정 |
| vulnerabilities:read, vuln:read | 취약점 조회 |
| vulnerabilities:write, vuln:write | 취약점 변경 |
| reports:read, report:read | 리포트 조회 |
| reports:write, report:write | 리포트 생성 |
| policies:read | 정책 조회 |
| policies:write | 정책 변경 |
| admin | 조직 관리자 수준 API 접근 |

### 6.3 운영 원칙

- SYSTEM_ADMIN은 최소 인원만 부여합니다.
- 조직별 관리자는 ORG_ADMIN으로 분리합니다.
- 프로젝트 책임자는 PROJECT_ADMIN으로 제한합니다.
- 자동화 토큰은 필요한 권한만 부여합니다.
- 퇴사자/이동자는 즉시 권한을 회수합니다.

## 7. 프로젝트 관리

관리자는 전체 프로젝트를 조회하고 관리할 수 있습니다.

### 7.1 프로젝트 목록

확인 항목:

- 프로젝트명
- Slug
- 조직
- 설명
- 위험도
- 취약점 수
- 마지막 스캔
- 라이선스 현황

### 7.2 프로젝트 생성

1. `프로젝트 관리`로 이동합니다.
2. `프로젝트 추가`를 클릭합니다.
3. 프로젝트 이름, slug, 조직, 설명을 입력합니다.
4. 저장합니다.

### 7.3 프로젝트 수정

수정 가능 항목:

- 프로젝트명
- slug
- 조직
- 설명

프로젝트를 다른 조직으로 이동하면 접근 권한과 정책 적용 범위가 달라질 수 있습니다.

### 7.4 프로젝트 삭제

프로젝트 삭제는 관련 스캔, 취약점, 라이선스 데이터 삭제로 이어질 수 있습니다.

운영 환경에서는 다음을 먼저 수행합니다.

1. 필요한 리포트 export
2. 스캔 결과 백업
3. 담당자/소유자 확인
4. 삭제 승인 기록

## 8. 보안 정책 관리

정책은 스캔 결과를 평가해 위험 기준을 자동 판단하는 기능입니다.

### 8.1 정책 범위

정책은 다음 범위로 운영할 수 있습니다.

- 전역
- 조직
- 프로젝트
- 환경별

환경 값:

- ALL
- DEVELOPMENT
- STAGING
- PRODUCTION

### 8.2 정책 생성

1. `보안 정책`으로 이동합니다.
2. `정책 추가`를 클릭합니다.
3. 이름, 설명, 적용 범위, 환경을 입력합니다.
4. 규칙을 추가합니다.
5. 활성화 여부를 지정합니다.
6. 저장합니다.

### 8.3 정책 규칙 예시

| 규칙 | 설명 |
| --- | --- |
| Critical 취약점 허용 개수 0 | Critical이 있으면 정책 위반 |
| High 취약점 최대 N개 | High가 기준 이상이면 위반 |
| 특정 라이선스 차단 | GPL/AGPL 등 지정 라이선스 탐지 시 위반 |
| 수정 가능 취약점 차단 | fixedVersion이 있는 취약점이 남아 있으면 위반 |
| 만료된 예외 차단 | 예외 만료 후 다시 위반 처리 |

### 8.4 정책 수정

정책 수정 시 기존 스캔 결과에 대한 평가 기준이 바뀔 수 있습니다. 변경 후 대표 프로젝트에서 정책 평가를 다시 실행해 의도한 결과인지 확인합니다.

### 8.5 정책 삭제

정책 삭제는 관련 예외와 평가 결과에 영향을 줄 수 있습니다. 삭제 전 정책을 비활성화하고 일정 기간 모니터링하는 것을 권장합니다.

### 8.6 정책 평가

정책 평가는 스캔 결과와 프로젝트를 기준으로 수행됩니다.

API 예시:

```bash
curl -X POST "$JASCA_URL/api/policies/evaluate" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"projectId":"<PROJECT_ID>","scanResultId":"<SCAN_ID>"}'
```

## 9. 예외 관리

예외 관리는 정책 위반 또는 취약점 조치 예외를 승인/반려하는 기능입니다.

### 9.1 예외 유형

| 유형 | 설명 |
| --- | --- |
| CVE 예외 | 특정 CVE에 대한 예외 |
| 패키지 예외 | 특정 패키지 전체 또는 특정 버전에 대한 예외 |
| 이미지 예외 | 특정 이미지 또는 artifact 대상 예외 |
| 심각도 예외 | 특정 심각도 이하 예외 |
| 정책 예외 | 특정 정책 규칙에 대한 예외 |

### 9.2 예외 검토 절차

1. `예외 관리`로 이동합니다.
2. 대기 중인 예외 요청을 확인합니다.
3. 요청 사유와 대상 값을 검토합니다.
4. 만료일이 적절한지 확인합니다.
5. 승인 또는 반려합니다.

### 9.3 승인 기준

승인은 다음 조건을 만족할 때만 권장합니다.

- 업무 영향도가 명확함
- 임시 허용 기간이 정해짐
- 보완 통제가 있음
- 담당자와 재검토 일정이 있음

### 9.4 반려 기준

다음 경우 반려합니다.

- 사유가 불충분함
- 만료일이 없음
- Critical 취약점인데 조치 계획이 없음
- 전사 정책을 우회할 위험이 큼

## 10. 워크플로우 관리

워크플로우는 취약점 상태 전환과 담당자 조치 흐름을 관리합니다.

### 10.1 기본 상태 흐름

```text
OPEN -> ASSIGNED -> IN_PROGRESS -> FIX_SUBMITTED -> VERIFYING -> FIXED -> CLOSED
```

예외 흐름:

```text
OPEN -> IGNORED
OPEN -> FALSE_POSITIVE
```

### 10.2 운영 방식

- 신규 취약점은 OPEN으로 생성됩니다.
- 관리자는 담당자를 지정해 ASSIGNED로 전환합니다.
- 담당자는 조치 시작 시 IN_PROGRESS로 변경합니다.
- 수정 후 FIX_SUBMITTED로 변경합니다.
- 보안 담당자는 VERIFYING 또는 FIXED로 검증합니다.
- 종료 조건을 만족하면 CLOSED로 전환합니다.

### 10.3 증빙 관리

취약점 댓글 또는 fix evidence에 다음을 기록합니다.

- 수정 커밋
- 배포 버전
- 재스캔 결과
- 담당자 확인
- 예외 승인 번호

## 11. 컴플라이언스

컴플라이언스 메뉴는 조직별 보안 기준 준수 현황을 확인하는 기능입니다.

확인 항목:

- 조직별 정책 준수율
- 정책 위반 수
- 심각도별 분포
- 평균 조치 시간
- 예외 승인 현황
- 감사 대상 항목

운영 권장:

- 월별 리포트 생성
- Critical/High SLA 확인
- 예외 만료 예정 항목 점검
- 정책 변경 후 준수율 재확인

## 12. 취약점 관리

관리자 취약점 메뉴는 전체 취약점을 운영 관점에서 관리합니다.

가능 작업:

- 조직/프로젝트별 취약점 조회
- CVE ID 검색
- 패키지명 검색
- 심각도 필터
- 상태 필터
- 담당자 지정
- 상태 변경
- 댓글과 이력 확인
- 최신 스캔 기준 취약점 확인

운영자는 Critical과 High를 우선 처리하고, `fixedVersion`이 있는 항목을 조치 우선순위로 두는 것을 권장합니다.

## 13. 라이선스 관리

라이선스 관리는 오픈소스 라이선스 카탈로그와 프로젝트별 검출 결과를 관리하는 기능입니다.

### 13.1 라이선스 카탈로그

확인/관리 항목:

- 라이선스 이름
- SPDX ID
- 분류
- 위험도
- 설명
- URL

라이선스 분류 예시:

- Permissive
- Copyleft
- Strong Copyleft
- Proprietary
- Unknown

### 13.2 라이선스 수정

라이선스 목록에서 작업 버튼을 눌러 라이선스 메타데이터를 수정할 수 있습니다.

수정 대상:

- 분류
- 위험도
- 설명
- 참고 URL

### 13.3 기본 라이선스 seed

기본 라이선스 카탈로그가 비어 있거나 초기화가 필요한 경우 seed 기능을 사용합니다.

주의:

- 운영 중 이미 수동 분류한 값이 있으면 덮어쓰기 여부를 확인합니다.
- seed 후 대표 프로젝트의 라이선스 결과를 다시 확인합니다.

### 13.4 프로젝트별 라이선스

프로젝트별 탭에서 최신 스캔 기준 라이선스 요약을 확인합니다.

확인 항목:

- 프로젝트명
- 라이선스 수
- 위험 라이선스 수
- UNKNOWN 수
- 패키지 상세

운영 권장:

- UNKNOWN 라이선스를 주기적으로 분류합니다.
- GPL/AGPL 계열은 배포 전 검토합니다.
- 라이선스 정책과 연동해 차단 기준을 정합니다.

## 14. 수동 취약점 관리

수동 취약점은 Trivy DB에 아직 반영되지 않았거나 외부에서 별도로 받은 취약점 정보를 JASCA에 직접 적용하는 기능입니다.

### 14.1 사용 시나리오

- 신규 CVE가 Trivy DB에 반영되기 전 임시 적용
- 사내 보안 권고 등록
- 특정 제품/패키지에 대한 자체 취약점 등록
- 외부 보안 공지 기반 긴급 대응

### 14.2 수동 취약점 등록

필수/권장 입력:

- CVE ID 또는 내부 권고 ID
- 제목
- 설명
- 심각도
- 패키지명
- 영향 버전
- 수정 버전
- 참조 URL
- 적용 조직 또는 프로젝트
- 활성화 여부

### 14.3 일괄 등록 API

JSON 배열 또는 `{ "items": [...] }` 형태로 등록할 수 있습니다.

```bash
curl -X POST "$JASCA_URL/api/manual-advisories/bulk" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d @manual-advisories.json
```

### 14.4 파일 업로드

CSV 또는 JSON 파일로 업로드할 수 있습니다.

```bash
curl -X POST "$JASCA_URL/api/manual-advisories/upload" \
  -H "Authorization: Bearer <TOKEN>" \
  -F "file=@manual-advisories.csv"
```

파일 크기 제한은 1MB입니다.

### 14.5 운영 주의

- 수동 취약점은 Trivy DB 업데이트와 별개로 JASCA 내에서 적용됩니다.
- Trivy DB가 최신화되면 중복 여부를 확인합니다.
- 임시 권고는 만료일 또는 비활성화 기준을 정합니다.

## 15. AI 설정

AI 설정은 JASCA의 AI 요약, 분석, 정책 해석, 조치 추천 기능에 사용할 모델 연결을 관리합니다.

### 15.1 지원 공급자

환경에 따라 다음 유형을 사용할 수 있습니다.

- vLLM
- OpenAI 호환 API
- Ollama
- Anthropic
- Mock fallback

폐쇄망에서는 사내에서 서빙 중인 vLLM 또는 OpenAI compatible endpoint를 사용하는 것을 권장합니다.

### 15.2 필수 설정

| 항목 | 설명 |
| --- | --- |
| Provider | vLLM, OpenAI compatible, Ollama 등 |
| API URL | 사내 모델 서버 URL |
| Model | 모델명 |
| API Key | 필요 시 인증 키 |
| Timeout | 호출 제한 시간 |
| Max Tokens | 최대 출력 토큰 |

### 15.3 vLLM 예시

```text
Provider: vllm
API URL: http://ai-server.internal:8000/v1
Model: Qwen3-32B
API Key: 필요 시 입력
```

### 15.4 연결 테스트

1. AI 설정을 입력합니다.
2. `연결 테스트`를 실행합니다.
3. 실패 시 컨테이너 내부에서 URL 접근이 되는지 확인합니다.

컨테이너 내부 테스트 예시:

```bash
docker exec -it jasca curl -v http://ai-server.internal:8000/v1/models
```

### 15.5 AI 호출 실패 시

로그 예시:

```text
AI Call Failed, falling back to mock
vLLM 서버 연결 실패
Model: mock-model-v1(fallback)
```

확인 순서:

1. API URL이 컨테이너 내부에서 접근 가능한지 확인합니다.
2. DNS 또는 `/etc/hosts`가 필요한지 확인합니다.
3. 방화벽과 포트를 확인합니다.
4. 모델명이 실제 서버에 존재하는지 확인합니다.
5. API Key가 필요한지 확인합니다.
6. 모델 응답이 OpenAI compatible 형식인지 확인합니다.

### 15.6 thinking 출력 제거

일부 모델은 `<think>...</think>` 또는 reasoning 텍스트를 반환할 수 있습니다.

관리자는 다음 중 하나를 적용합니다.

- 모델 서버에서 thinking 출력 비활성화
- 시스템 프롬프트에 reasoning 비출력 지시 추가
- JASCA 응답 후처리에서 think 블록 제거
- 프롬프트 관리에서 출력 형식을 JSON 또는 Markdown 요약으로 제한

## 16. AI 프롬프트 관리

AI 프롬프트 관리는 기능별 AI 지시문을 수정하는 메뉴입니다.

관리 대상 예시:

- 취약점 요약
- 위험도 분석
- 조치 권고
- 정책 해석
- 정책 추천
- Trivy 명령 생성
- 권한 추천
- 컴플라이언스 매핑

운영 원칙:

- 프롬프트 변경 전 기존 내용을 백업합니다.
- 출력 형식과 금지사항을 명확히 적습니다.
- 폐쇄망 정보가 외부로 나가지 않도록 외부 API 사용 여부를 통제합니다.
- 변경 후 대표 취약점으로 테스트합니다.

## 17. AI 실행 이력

AI 실행 이력에서 다음을 확인합니다.

- 실행 시간
- 실행 사용자
- AI action
- 모델명
- 성공/실패
- fallback 여부
- 입력/출력 토큰
- 오류 메시지
- 실행 시간

운영자는 실패 이력을 기준으로 모델 서버 장애, 프롬프트 오류, 네트워크 문제를 추적합니다.

## 18. Trivy 설정

Trivy 설정은 서버에서 직접 검사할 때 적용되는 기본값을 관리합니다.

### 18.1 설정 항목

| 항목 | 설명 | 권장값 |
| --- | --- | --- |
| outputFormat | Trivy 출력 형식 | json |
| schemaVersion | 결과 스키마 버전 | 2 |
| severities | 표시할 심각도 | CRITICAL,HIGH,MEDIUM,LOW |
| scanners | 검사 종류 | vuln,license |
| ignoreUnfixed | 수정 버전 없는 취약점 제외 | false |
| timeout | 검사 제한 시간 | 10m~60m |
| cacheDir | Trivy DB cache dir | /app/trivy-db |

### 18.2 폐쇄망 권장 설정

```text
cacheDir=/app/trivy-db
scanners=vuln,license
offlineScan=true
skipDbUpdate=true
skipJavaDbUpdate=true
```

### 18.3 Scanner 선택

| scanner | 설명 |
| --- | --- |
| vuln | CVE 취약점 |
| license | 라이선스 |
| misconfig | 설정 오류 |
| secret | 비밀키/토큰 |

기본값은 `vuln`, `license`입니다. `misconfig`, `secret`은 검사 시간이 늘 수 있으므로 선택 사항으로 운영합니다.

## 19. Trivy DB 운영

### 19.1 DB 위치

폐쇄망 운영에서는 서버의 Trivy DB를 컨테이너에 mount합니다.

예시:

```bash
-v /sw/dify/.cache/trivy:/app/trivy-db
```

### 19.2 DB 구조

일반적으로 다음 파일이 필요합니다.

```text
/app/trivy-db/db/trivy.db
/app/trivy-db/db/metadata.json
/app/trivy-db/java-db/trivy-java.db
/app/trivy-db/java-db/metadata.json
```

환경에 따라 flat 구조도 허용됩니다.

```text
/app/trivy-db/trivy.db
/app/trivy-db/metadata.json
```

### 19.3 DB 갱신

폐쇄망에서는 외부망에서 DB를 갱신한 뒤 파일을 반입합니다.

운영 절차:

1. 외부망에서 Trivy DB 다운로드 또는 갱신
2. DB 파일 무결성 확인
3. 폐쇄망 서버로 반입
4. JASCA 컨테이너 mount 경로에 배치
5. Trivy DB 메뉴에서 UpdatedAt 확인
6. 대표 파일로 스캔 테스트

## 20. 알림 설정

알림 설정은 취약점, 정책, 예외, 리포트 이벤트를 사용자 또는 외부 채널에 전달하는 기능입니다.

관리 항목:

- 알림 채널
- 알림 규칙
- 이벤트 유형
- 심각도 기준
- 수신 대상
- 활성화 여부

알림 이벤트 예시:

- Critical 취약점 발견
- 정책 위반
- 예외 요청
- 예외 승인/반려
- 담당자 지정
- 리포트 생성 완료

## 21. CI/CD 연동

CI/CD 연동 메뉴는 JASCA API를 이용해 파이프라인에서 스캔 결과를 자동 업로드하는 방법을 안내합니다.

### 21.1 권장 연동 방식

폐쇄망에서는 다음 방식 중 하나를 선택합니다.

| 방식 | 설명 |
| --- | --- |
| CI에서 Trivy 실행 후 결과 업로드 | CI 서버에 Trivy DB가 있을 때 권장 |
| JASCA로 검사 대상 업로드 | JASCA 서버의 Trivy DB로 중앙 검사할 때 권장 |

### 21.2 API 토큰 생성

CI 전용 토큰에는 필요한 최소 권한만 부여합니다.

권장 권한:

- scan:upload
- scan:read
- project:read
- project:write가 필요한 경우에만 추가

### 21.3 업로드 예시

```bash
trivy fs --format json --output trivy-result.json .

curl -X POST "$JASCA_URL/api/scans/upload/file?projectName=$PROJECT_NAME" \
  -H "Authorization: Bearer $JASCA_TOKEN" \
  -F "file=@trivy-result.json" \
  -F "sourceType=TRIVY_JSON"
```

## 22. API 토큰 관리

관리자는 조직 또는 시스템 연동에 필요한 API 토큰을 관리합니다.

### 22.1 토큰 생성 기준

- 목적별로 토큰을 분리합니다.
- 만료일을 설정합니다.
- 최소 권한만 부여합니다.
- 토큰 원문은 안전한 비밀 저장소에 보관합니다.

### 22.2 토큰 삭제 기준

- 담당자 퇴사
- CI/CD 파이프라인 폐기
- 토큰 유출 의심
- 권한 변경 필요

삭제 후 관련 파이프라인이 실패하지 않도록 새 토큰을 먼저 반영합니다.

## 23. API Explorer

API Explorer는 관리자 또는 개발자가 JASCA API를 확인하고 테스트하는 화면입니다.

사용 목적:

- 엔드포인트 목록 확인
- 요청 파라미터 확인
- 인증 헤더 확인
- API 응답 구조 확인
- 연동 전 사전 테스트

주의:

- 운영 데이터 변경 API는 테스트 조직/프로젝트에서 먼저 실행합니다.
- DELETE, PUT, POST 요청은 영향 범위를 확인합니다.
- API 토큰은 화면 공유나 로그에 노출하지 않습니다.

## 24. SSO 설정

SSO 설정은 로그인 방식을 중앙 인증과 연동하는 기능입니다.

### 24.1 전역 SSO 설정

설정 항목:

- SSO 로그인 활성화
- Provider 활성화 여부
- 기본 역할
- 자동 사용자 생성 여부
- 허용 도메인

### 24.2 Keycloak 설정

필수 항목:

- Server URL
- Realm
- Client ID
- Client Secret
- Redirect URI
- 사용자 동기화 여부
- 그룹/역할 매핑

### 24.3 LDAP 설정

필수 항목:

- LDAP URL
- Bind DN
- Bind Password
- User Search Base
- User Search Filter
- User ID Attribute
- Group Search Base
- Group Mapping

### 24.4 운영 주의

- SSO 변경 전 로컬 관리자 계정을 하나 유지합니다.
- Redirect URI는 실제 접속 URL과 일치해야 합니다.
- 폐쇄망 DNS에서 SSO 서버가 컨테이너 내부에서도 접근 가능해야 합니다.

## 25. 감사 로그

감사 로그는 시스템 내 주요 작업과 변경 이력을 추적합니다.

조회 항목:

- 작업 시간
- 사용자
- 조직
- 액션
- 리소스 유형
- 리소스 ID
- 상세 정보
- IP

필터:

- 사용자
- 조직
- 액션
- 리소스
- 기간

운영 권장:

- 관리자 권한 변경 이력 주기 점검
- 정책 변경 이력 보관
- 예외 승인/반려 이력 확인
- 토큰 생성/삭제 이력 확인

## 26. 데이터베이스 관리

데이터베이스 메뉴는 JASCA 내부 DB 상태를 확인하는 운영 진단 기능입니다.

확인 항목:

- DB 연결 상태
- 테이블 목록
- 레코드 수
- 주요 모델 상태
- 마이그레이션/스키마 정보

주의:

- 운영 DB 직접 변경은 권장하지 않습니다.
- 문제 발생 시 먼저 백업을 확보합니다.
- Prisma migration과 실제 DB 상태가 맞는지 확인합니다.

## 27. 스키마 관리

스키마 메뉴는 데이터 모델과 ERD를 확인하는 기능입니다.

주요 영역:

- 조직/프로젝트
- 사용자/인증
- 스캔/취약점
- 정책/예외
- 워크플로우
- 알림
- 설정/기타

활용:

- 장애 분석
- API 연동 설계
- 리포트 요구사항 분석
- 데이터 보존 정책 검토

## 28. 관리자 사이트맵

관리자 사이트맵은 관리자 메뉴 전체 구조를 한눈에 확인하는 화면입니다.

활용:

- 신규 관리자 교육
- 메뉴 위치 확인
- 권한별 접근 범위 설명
- 운영 점검 체크리스트 작성

## 29. 폐쇄망 배포 운영

### 29.1 기존 서비스 구조

기존 운영 정보 예시:

```bash
docker run -d \
  --name jasca \
  --restart unless-stopped \
  -p 3005:3000 \
  -e CORS_ORIGIN="https://jasca.koreacb.com" \
  -e PORT=3001 \
  -e JWT_SECRET="jasca_offline_secret" \
  -e REDIS_URL="redis://localhost:6379" \
  -e DATABASE_URL="postgresql://jasca:jasca_secret@localhost:5432/jasca" \
  -v /app/jasca/pgdata:/var/lib/postgresql/data \
  -v /app/jasca/redis:/var/lib/redis \
  -v /etc/hosts:/etc/hosts \
  jasca-offline:latest
```

### 29.2 데이터 볼륨

| 경로 | 저장 내용 |
| --- | --- |
| `/app/jasca/pgdata` | PostgreSQL 데이터, 사용자, 조직, 프로젝트, 스캔, 취약점, 정책, 설정 |
| `/app/jasca/redis` | Redis 데이터, 캐시/세션/큐 관련 데이터 |
| Trivy cache mount 경로 | Trivy DB와 Java DB |

재배포 시 소스 코드만 바꾸는 것이 아니라 새 Docker image를 load하고 기존 볼륨을 유지한 채 컨테이너를 재기동합니다.

### 29.3 새 이미지 반입

1. Release에서 `jasca-offline.tar.gz`를 다운로드합니다.
2. 폐쇄망 서버 `/app/jasca`에 반입합니다.
3. 해시를 확인합니다.

```bash
cd /app/jasca
sha256sum jasca-offline.tar.gz
```

4. 이미지를 로드합니다.

```bash
gunzip -c jasca-offline.tar.gz | docker load
```

5. 이미지 확인:

```bash
docker images | grep jasca-offline
```

### 29.4 재기동 예시

```bash
cd /app/jasca

docker stop jasca
docker rm jasca

docker run -d \
  --name jasca \
  --restart unless-stopped \
  -p 3005:3000 \
  -e CORS_ORIGIN="https://jasca.koreacb.com" \
  -e PORT=3001 \
  -e JWT_SECRET="jasca_offline_secret" \
  -e DB_PASSWORD="jasca_secret" \
  -e REDIS_URL="redis://localhost:6379" \
  -e DATABASE_URL="postgresql://jasca:jasca_secret@localhost:5432/jasca" \
  -e TRIVY_UPLOAD_MAX_BYTES="2GB" \
  -e TRIVY_CACHE_DIR="/app/trivy-db" \
  -v /app/jasca/pgdata:/var/lib/postgresql/data \
  -v /app/jasca/redis:/var/lib/redis \
  -v /sw/dify/.cache/trivy:/app/trivy-db \
  -v /etc/hosts:/etc/hosts \
  jasca-offline:latest

docker logs -f jasca
```

`DB_PASSWORD`는 현재 이미지에서 필수입니다. 기존 `DATABASE_URL`과 동일한 DB 비밀번호를 넣습니다.

### 29.5 롤백

이전 이미지가 남아 있는 경우:

```bash
docker stop jasca
docker rm jasca
docker run -d ... 이전 이미지 태그 ...
```

이전 image tar가 있는 경우:

```bash
gunzip -c jasca-offline-old.tar.gz | docker load
docker stop jasca
docker rm jasca
docker run -d ... jasca-offline:previous
```

데이터 볼륨을 유지하면 기존 DB 데이터는 유지됩니다. 단, 새 버전에서 DB migration이 수행된 경우 이전 버전과 완전 호환되지 않을 수 있으므로 운영 전 백업을 권장합니다.

## 30. 운영 점검 체크리스트

### 30.1 일일 점검

- 컨테이너 상태 확인: `docker ps`
- 로그 오류 확인: `docker logs jasca --tail 200`
- Trivy DB 상태 확인
- Critical/High 신규 발생 확인
- 실패한 스캔 확인
- AI 호출 실패 확인

### 30.2 주간 점검

- 사용자/권한 변경 검토
- 예외 만료 예정 확인
- API 토큰 만료 예정 확인
- 라이선스 UNKNOWN 분류
- 정책 위반 추세 확인
- 리포트 생성 및 공유

### 30.3 월간 점검

- Trivy DB 최신화 반입
- 수동 취약점 중복/만료 정리
- SSO/LDAP 동기화 점검
- 감사 로그 검토
- 백업/복구 리허설

## 31. 장애 대응

### 31.1 서비스 접속 불가

확인 순서:

```bash
docker ps
docker logs jasca --tail 200
curl -I http://localhost:3005
```

확인 항목:

- 컨테이너 실행 여부
- 포트 충돌
- DB 초기화 실패
- Redis 실패
- 환경변수 누락

### 31.2 DB_PASSWORD 오류

오류:

```text
DB_PASSWORD must be provided
```

해결:

```bash
-e DB_PASSWORD="jasca_secret"
```

`DATABASE_URL`의 비밀번호와 일치시킵니다.

### 31.3 Trivy DB 오류

오류:

```text
Trivy vulnerability DB is not available
```

확인:

```bash
docker exec -it jasca ls -lah /app/trivy-db
docker exec -it jasca find /app/trivy-db -maxdepth 3 -type f
```

해결:

- DB mount 경로 수정
- `TRIVY_CACHE_DIR=/app/trivy-db` 지정
- DB 파일 구조 확인
- DB metadata 존재 확인

### 31.4 업로드 용량 오류

오류:

```text
Upload Failed
file too large
```

해결:

```bash
-e TRIVY_UPLOAD_MAX_BYTES="2GB"
```

프록시가 앞단에 있다면 Nginx/Ingress의 body size 제한도 함께 조정합니다.

### 31.5 AI 연결 실패

확인:

```bash
docker exec -it jasca curl -v http://사내AI서버:포트/v1/models
```

필요 시 `/etc/hosts` mount 또는 DNS 설정을 확인합니다.

## 32. 보안 운영 원칙

- 관리자 계정은 MFA를 활성화합니다.
- SYSTEM_ADMIN은 최소 인원만 유지합니다.
- API 토큰은 목적별로 분리하고 만료일을 설정합니다.
- 폐쇄망에서도 Trivy DB 반입 이력을 기록합니다.
- 예외는 반드시 만료일과 사유를 둡니다.
- 정책 변경은 감사 로그와 변경 승인 기록을 남깁니다.
- 스캔 업로드 파일은 검사 후 자동 삭제되는 구조를 유지합니다.
- 운영 DB와 Redis 볼륨은 정기적으로 백업합니다.

