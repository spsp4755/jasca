# Task 2 Harbor Trivy Scanning Report

## Status

Implemented and committed Harbor image-reference scanning and the public default-format Harbor Push Artifact webhook.

Commit: `a8cbc7e` (`feat: scan Harbor images with Trivy`)

## TDD Evidence

### RED

Command run from `apps/api`:

```powershell
node_modules\.bin\jest.cmd --runInBand modules/harbor/harbor-scan.service.spec.ts modules/scans/services/trivy-scan.service.spec.ts
```

Result: exit code 1 for the expected missing-feature reasons:

- `TS2307`: `./harbor-scan.service` did not exist.
- `TS2339`: `TrivyScanService.scanImageReference` did not exist.

### GREEN

Focused command run from `apps/api`:

```powershell
node_modules\.bin\jest.cmd --runInBand modules/harbor/harbor-scan.service.spec.ts modules/harbor/harbor.service.spec.ts modules/scans/services/trivy-scan.service.spec.ts modules/scans/services/trivy-sbom-artifact.spec.ts
```

Result: exit code 0. `4/4` suites and `22/22` tests passed.

Full API command:

```powershell
node_modules\.bin\jest.cmd --runInBand
```

Result: exit code 0. `19/19` suites and `134/134` tests passed. The suite emitted existing Semgrep test warnings for mocked fallback and cleanup behavior; no tests failed.

## Build Verification

Command run from `apps/api`:

```powershell
node_modules\.bin\nest.cmd build
```

Result: exit code 0. `git diff --cached --check` also exited 0 before commit.

## Implementation

- Added offline Trivy `image` JSON scanning for immutable image references with existing timeout, cancellation, cache, evidence, bounded-output, and error handling.
- Passed Harbor credentials only through `TRIVY_USERNAME` and `TRIVY_PASSWORD` in the child process environment; command evidence excludes credentials and errors redact them.
- Added `HarborScanService.scan` using `ScansService.uploadScan` with `TRIVY_JSON`, immutable digest, image reference, tag, requester attribution, and `Metadata.JascaScanEvidence.harbor.trigger`.
- Added Bearer-secret verification using `timingSafeEqual` over SHA-256 digests. No payload HMAC is implemented.
- Added parsing for Harbor's default `PUSH_ARTIFACT` payload fields: repository namespace/name and resource digest/tag/resource URL.
- Added validation for disabled integration/auto-scan, invalid authorization, unsupported events, unapproved Harbor projects, missing/invalid digest, registry scope, and missing/invalid default JASCA project.
- Added process-local active scan deduplication and database-backed recent completion deduplication for the same JASCA project, full image reference, and digest.
- Exposed only `POST /api/harbor/webhook` without JWT guards by using a separate webhook controller; existing Harbor administration routes retain their class-level JWT and role guards.

## Files Committed

- `apps/api/src/modules/harbor/harbor-scan.service.ts`
- `apps/api/src/modules/harbor/harbor-scan.service.spec.ts`
- `apps/api/src/modules/harbor/harbor.controller.ts`
- `apps/api/src/modules/harbor/harbor.module.ts`
- `apps/api/src/modules/scans/services/trivy-scan.service.ts`
- `apps/api/src/modules/scans/services/trivy-scan.service.spec.ts`
- `apps/api/src/modules/scans/scans.module.ts`

## Concerns

Active-scan deduplication is process-local because the existing schema has no running-scan or lock record and this task prohibited migrations. Recently completed deduplication is database-backed for 10 minutes and can be configured with `HARBOR_SCAN_DEDUP_TTL_MS`. A future multi-instance deployment would need a distributed lock to guarantee active deduplication across API replicas.

Unrelated pre-existing design, plan, report, and release artifact changes remain unstaged and were not included in the commit.

---

## Review Fixes

Implemented all four Task 2 review findings and committed them separately.

Commit: `6de22df` (`fix: harden Harbor scan execution`)

### Changes

- Added authenticated `POST /api/harbor/scan` handling for scan-capable roles. The controller sanitizes the request body, and `HarborScanService.scan` now requires the authenticated `RequestUser`, enforces `assertProjectAccess`, derives `uploadedById` from that user, and passes the user to `ScansService.uploadScan`. Client-supplied `requestedById` is not part of the contract and is ignored. Webhooks pass no user attribution.
- Added cross-replica active-scan deduplication with PostgreSQL `pg_try_advisory_lock` and `pg_advisory_unlock` through Prisma raw queries. The two-part lock key is derived from a SHA-256 hash of the JASCA project ID and immutable repository-at-Digest reference. An interactive Prisma transaction pins lock and unlock to the same database session, and release occurs in `finally`.
- Restricted recent-scan deduplication to rows with a persisted `ScanSummary` using `summary: { isNot: null }`, so partial rows left before downstream processing completed do not block retries.
- Explicitly passes undefined `TRIVY_USERNAME` and `TRIVY_PASSWORD` overrides for Harbor image scans, and removes undefined overrides from the inherited process environment before spawning Trivy. Configured Harbor credentials are then set only for that child process.
- Added controller and service regressions for sanitization, requester attribution, project access, cross-instance lock contention, lock release on failure, completed-only deduplication, incomplete-row retry, and inherited Trivy credential clearing.

### TDD Evidence

The new tests failed before implementation for the expected reasons: the manual scan controller method was missing, manual scans trusted `requestedById` and skipped project access, recent deduplication did not require a summary, separate service instances both executed Trivy, no advisory unlock ran on failure, and no explicit Trivy environment-clearing overrides were supplied.

Focused verification from `apps/api`:

```powershell
node_modules\.bin\jest.cmd --runInBand modules/harbor/harbor.controller.spec.ts modules/harbor/harbor-scan.service.spec.ts modules/harbor/harbor.service.spec.ts modules/scans/services/trivy-scan.service.spec.ts modules/scans/services/trivy-sbom-artifact.spec.ts
```

Result: exit code 0. `5/5` suites and `28/28` tests passed.

Full API verification:

```powershell
node_modules\.bin\jest.cmd --runInBand
```

Result: exit code 0. `20/20` suites and `140/140` tests passed. Existing Semgrep mocked warning output remained non-failing.

API build:

```powershell
npm.cmd run build
```

Result: exit code 0.

`git diff --cached --check` also exited 0 before commit.

### Concerns

No blocker remains. Session-level PostgreSQL advisory locking requires pinning one Prisma interactive-transaction connection for each active Harbor scan; the transaction timeout is 24 hours so normal Trivy timeouts can complete. No migration or dependency was added. Unrelated design, plan, SDD, and release artifact changes remain outside commit `6de22df`.

---

## Durable Harbor Job Migration Fix

### Status

Replaced PostgreSQL advisory locking and the long interactive transaction with a durable `HarborScanJob` lifecycle backed by an additive Prisma migration.

### Changes

- Added `HarborScanJobStatus` and `HarborScanJob`, including project and scan-result relations, the unique `(projectId, imageDigest)` key, and indexes for stale-job and scan-result access.
- Added migration `20260715120000_add_harbor_scan_jobs`; it creates only the new enum, table, indexes, and foreign keys and does not alter existing tables or columns.
- Creates a `RUNNING` job before Trivy starts. A fresh `RUNNING` collision returns duplicate without invoking Trivy.
- Atomically claims `FAILED` jobs and completed jobs older than `HARBOR_SCAN_DEDUP_TTL_MS`. `RUNNING` jobs older than `HARBOR_SCAN_JOB_STALE_TTL_MS` are first marked `FAILED`, then become retryable. The stale TTL defaults to 24 hours.
- Uses the attempt's `startedAt` value as an ownership token for terminal updates, preventing an old worker from overwriting a replacement attempt after stale recovery.
- Marks a job `COMPLETED` only after `ScansService.uploadScan` returns. Scanner and upload persistence errors mark the owned attempt `FAILED` with Harbor credentials redacted before the original error is rethrown.
- Preserved authenticated manual project authorization and webhook routing through the configured default project.
- Removed the process-local active set, advisory-lock raw SQL, and interactive Prisma transaction from the Harbor scan flow.

### TDD Evidence

RED command from `apps/api`:

```powershell
node_modules\.bin\jest.cmd --runInBand modules/harbor/harbor-scan.service.spec.ts
```

Result: exit code 1 with `5` expected failures and `10` passing tests. The failures showed that no durable job existed before Trivy, a unique `RUNNING` collision still scanned, failures were not finalized/redacted, stale jobs were not reclaimed, and recent completed jobs were not deduplicated from job state.

GREEN focused command:

```powershell
node_modules\.bin\jest.cmd --runInBand modules/harbor
```

Result: exit code 0. `3/3` suites and `24/24` tests passed.

### Verification

- Full API Jest: `node_modules\.bin\jest.cmd --runInBand` passed `20/20` suites and `142/142` tests. Existing mocked Semgrep warnings remained non-failing.
- Prisma client: `npm.cmd run prisma:generate` succeeded with Prisma Client `5.22.0`.
- API build: `npm.cmd run build` completed successfully.
- Scoped `git diff --check` completed without whitespace errors.

### Concerns

No blocker remains. Deployments must apply the additive Prisma migration before running this API version. Operators whose valid Harbor scans can exceed 24 hours should set `HARBOR_SCAN_JOB_STALE_TTL_MS` above their maximum scan and persistence duration.
