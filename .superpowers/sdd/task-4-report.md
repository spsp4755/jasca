# Task 4 Harbor Integration Verification Report

## Status

Task 4 integration verification and offline operations documentation are complete. No production-code fix was required after reviewing the committed Task 1-3 Harbor registry, scan/persistence, durable duplicate-job, authorization, and UI changes.

## Integration Coverage

Added `apps/api/src/modules/harbor/harbor.integration.spec.ts`. The test starts a Nest HTTP application with the production Harbor controllers, `HarborScanService`, and `RolesGuard`. External boundaries use in-memory fakes for authenticated JWT identity injection, Harbor settings, Trivy output, project/job persistence, and scan-result persistence.

The test verifies in one API-level flow:

- Authenticated `POST /api/harbor/scan` persists a manual scan with authenticated-user attribution and `harbor.trigger=manual` evidence.
- A default Harbor `PUSH_ARTIFACT` request with the configured Bearer secret persists a webhook scan in the default JASCA project with `harbor.trigger=webhook` evidence.
- Repeating the webhook Digest returns `{ accepted: true, duplicate: true }` while Trivy and scan persistence remain at two calls total.
- An invalid webhook Bearer secret and a manual request without JWT authentication both return `401` without invoking another scan.

This verification test passed on its first run against the existing Task 1-3 implementation, so no production behavior was changed.

## Operations Guide

Updated `docker/monolith/README-OFFLINE.md` with Harbor deployment separation, automatic durable-job migration, firewall directions, HTTPS/internal-CA requirements, least-privilege robot-account scope, JASCA settings, exact Harbor `auth_header` configuration, and persistence/deduplication/auth QA steps.

The guide calls out that `NODE_EXTRA_CA_CERTS` covers the Node Harbor API client while Trivy must also trust the registry CA through OS trust or `SSL_CERT_FILE`. Operators must complete a manual image scan in addition to the connection test.

## Verification Results

Focused integration test from `apps/api`:

```powershell
node_modules\.bin\jest.cmd --runInBand modules/harbor/harbor.integration.spec.ts
```

Result: exit code 0; `1/1` suite and `1/1` test passed.

Focused Harbor API tests from `apps/api`:

```powershell
node_modules\.bin\jest.cmd --runInBand modules/harbor
```

Result: exit code 0; `4/4` suites and `25/25` tests passed.

Full API suite from `apps/api`:

```powershell
node_modules\.bin\jest.cmd --runInBand
```

Result: exit code 0; `21/21` suites and `143/143` tests passed. Existing mocked Semgrep fallback and cleanup warnings were non-failing.

API build from `apps/api`:

```powershell
npm.cmd run build
```

Result: exit code 0 (`nest build`).

Web build from `apps/web`:

```powershell
npm.cmd run build
```

Result: exit code 0. Next.js compiled, type-checked, and generated `54/54` static pages, including `/admin/harbor` and `/dashboard/scans/new`. The pre-existing stale Browserslist notice and Windows standalone-output `EPERM` symlink warnings remained non-fatal.

Scoped `git diff --check` exited 0. Git emitted only the repository's Windows LF-to-CRLF warning for `docker/monolith/README-OFFLINE.md`.

## Blockers

None. Harbor/Trivy live deployment QA still requires an environment with a reachable Harbor registry, valid robot pull credentials, trusted TLS, a populated offline Trivy DB, and an HTTPS webhook route; the committed API-level test deliberately replaces those external systems.

---

# JASCA AI Task 4 구현 보고서

## 상태

완료. 구조화된 PDF/DOCX, `summary`/`full` 범위, 원본 스캔 삭제 fallback, Linux Noto CJK 글꼴 경로, scan detail 컨텍스트를 구현했다.

## 구현

- 공통 `AiExportReport`에 `statistics`, `findings`, `scope`, `partial`을 추가했다.
- `summary`는 Critical/High 우선으로 최대 20건을 포함하고 전체/포함/생략 건수를 표시한다.
- `full`은 공통 `canAccessAiExecution` 권한 확인 후 `context.scanId`로 Prisma의 scan vulnerabilities와 licenses를 조회한다.
- 원본 scan이 없으면 저장 finding으로 fallback하고 일부 보고서 안내를 PDF/DOCX에 표시한다.
- PDF는 6열 표를 직접 렌더링하고 페이지 경계에서 행을 넘긴 뒤 헤더를 반복한다.
- DOCX는 `docx`의 실제 `Table`/`TableRow` 6열 표를 렌더링한다.
- 컨테이너 base apt layer에 `fonts-noto-cjk`를 추가하고 Linux TTC 및 Windows Malgun Gothic 후보를 지원한다.
- scan detail AI context에 `scanId`, `scanner`, `location`, `reference`를 저장한다.

## TDD

- RED: `npm.cmd test -- --runInBand modules/ai/ai-export.service.spec.ts`
  - 6건 실패: statistics/findings, DOCX table, full Prisma 조회, partial fallback, Linux TTC, 한국어 오류.
- RED: `npm.cmd test -- --runInBand modules/ai/ai.controller.spec.ts`
  - 3건 실패: summary/full/default scope 전달.
- GREEN: focused API tests 2 suites, 33 tests passed.

## 검증

- Full API tests: 27 suites, 220 tests passed.
- API build: `nest build` 성공.
- Web build: Next.js compile/type check/static generation 54 pages 성공, exit 0.
- `git diff --check`: 오류 없음.

## 우려사항

- Windows web build에서 standalone symlink 복사 `EPERM` 경고 2건이 있었으나 빌드는 exit 0이었다. Docker의 Linux builder에는 적용되지 않는 Windows 환경 경고다.
- 전체 monolith Docker image build는 이번 검증 범위에 포함하지 않았다. `fonts-noto-cjk` 설치와 실제 TTC 사용은 다음 Linux image build에서 최종 확인해야 한다.
