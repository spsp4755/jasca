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
