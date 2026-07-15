# Task 3 Report: Harbor Admin and Manual Scan UI

## Implemented

- Added `/admin/harbor` with Harbor URL, Robot Account, masked Robot Token and Webhook Secret fields, allowed Harbor projects, default JASCA project, auto-scan toggle, save action, and connection test.
- Added Harbor navigation to the admin sidebar.
- Added typed Harbor React Query hooks for settings, connection testing, project/repository/artifact browsing, and `POST /harbor/scan`.
- Added the Harbor scanner to the manual scan page. It follows JASCA project -> Harbor project -> repository -> immutable digest, treats tags as supplementary metadata, and does not render a file upload target.
- Documented the exact Push Artifact webhook endpoint and `Authorization: Bearer <Webhook Secret>` requirement; the page explicitly warns against Harbor HMAC signature headers.

## Verification

- `npm.cmd run build` in `apps/web` exited 0.
- The build generated `/admin/harbor` and `/dashboard/scans/new` successfully.
- The build emitted pre-existing Windows standalone-output symlink warnings (`EPERM`) and stale Browserslist data warnings, but completed successfully.
- `git diff --check` exited 0.

## Scope

- Staged task files are limited to the four assigned web paths and this report.
- Existing concurrent worktree changes were not modified or staged.

---

# Task 3 공통 한국어 AI 프롬프트

## 상태

완료

## 구현

- `buildAiPrompt(action, basePrompt)`가 모든 기본 및 관리자 지정 프롬프트에 공통 안전·보고서 규칙을 추가한다.
- 공통 규칙은 한국어 전용 출력, 근거 없는 수치·CVE·URL·참조 정보 금지, 내부 추론 미출력, `발견 없음`과 `확인 필요` 구분, 스캐너 구분 및 공통 제목을 포함한다.
- `scan.analysis`, `scan.changeAnalysis`, `report.generation`에는 스캐너별 6열 발견 사항 표, Critical/High 우선 최대 20건, 전체·표기·생략 건수 규칙을 추가한다.
- 관리자 프롬프트 저장 및 조회 API의 원문 저장 동작은 유지하고, 실행 시 `getPromptForAction`에서만 공통 규칙을 합성한다.

## TDD 및 검증

- RED 1: `buildAiPrompt` 미구현 상태에서 `TS2305` 실패를 확인했다.
- RED 2: 관리자 지정 프롬프트가 공통 규칙 없이 반환되는 회귀 테스트 실패를 확인했다.
- GREEN: `npm.cmd test -- --runInBand modules/ai/ai-actions.spec.ts` - 20개 통과.
- 전체 API 테스트: `npm.cmd test -- --runInBand` - 27개 스위트, 211개 테스트 통과.
- 빌드: `npm.cmd run build` - 성공.

## 우려사항

- 프롬프트 규칙은 모델 출력의 행동 지침이며, 공급자 응답에 대한 구조적 강제 검증은 이번 범위에 포함하지 않았다.
