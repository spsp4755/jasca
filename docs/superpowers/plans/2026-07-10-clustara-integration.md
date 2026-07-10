# Clustara Offline Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** JASCA의 Trivy 원본 결과와 생성된 Syft CycloneDX SBOM을 설정 가능한 사내 Clustara API로 비동기 전송하고 관리자 및 스캔 상세 UI에서 관리한다.

**Architecture:** 기존 `SystemSettings`에 마스킹된 Clustara 설정을 저장하고, PostgreSQL `ClustaraDelivery`를 outbox로 사용한다. `ClustaraService`가 URL·인증·재시도·중복 방지를 담당하고, `ScansService`는 결과 저장 후 전송 등록만 수행한다. Syft SBOM은 문자열로 스캔 경계를 통과한 후 `SCAN_RESULT_DIR/artifacts`에 영구 저장한다.

**Tech Stack:** NestJS 10, Prisma/PostgreSQL, Node `http`/`https`, Jest, Next.js 14, React Query, Tailwind CSS, Docker linux/amd64

## Global Constraints

- 기준 소스는 JASCA `v0.3.7`이다.
- 폐쇄망 런타임 외부 다운로드와 클라우드 호출을 추가하지 않는다.
- Clustara 장애는 JASCA 스캔 저장과 정책 평가를 실패시키지 않는다.
- 인증 비밀값은 조회 응답과 로그에 노출하지 않는다.
- 자동 전송에는 유효한 `cluster_id`와 `sha256:` 뒤 64자리 digest가 필요하다.
- 업로드 파일 SHA256을 OCI image digest로 사용하지 않는다.
- 새 메시지 브로커나 npm 의존성을 추가하지 않는다.

---

### Task 1: Prisma 전송 및 SBOM 아티팩트 모델

**Files:**
- Modify: `apps/api/prisma/schema.prisma`
- Create: `apps/api/prisma/migrations/20260710090000_add_clustara_integration/migration.sql`

**Interfaces:**
- Produces: `ClustaraDelivery`, `ScanArtifact`, `ClustaraDeliveryType`, `ClustaraDeliveryStatus`, `ScanArtifactType`
- Consumes: existing `ScanResult` relation

- [ ] **Step 1: Add schema models and relations**

Add `clustaraDeliveries ClustaraDelivery[]` and `artifacts ScanArtifact[]` to `ScanResult`. Define delivery fields for scan, type, status, query values, attempts, HTTP/error audit fields, retry timestamps, and a unique composite on `(scanResultId, type, clusterId, imageDigest)`. Define one CycloneDX artifact per scan/type with path, SHA256, generator, version, and timestamps.

- [ ] **Step 2: Add the SQL migration**

Create matching PostgreSQL enums, tables, foreign keys with `ON DELETE CASCADE`, indexes for `(status, nextAttemptAt)` and scan lookup, and both unique indexes.

- [ ] **Step 3: Validate and generate Prisma client**

Run: `pnpm --filter @jasca/api exec prisma validate`

Expected: `The schema at prisma/schema.prisma is valid`

Run: `pnpm --filter @jasca/api prisma:generate`

Expected: Prisma Client generation succeeds.

- [ ] **Step 4: Commit**

```powershell
git add apps/api/prisma/schema.prisma apps/api/prisma/migrations/20260710090000_add_clustara_integration/migration.sql
git commit -m "feat: add Clustara delivery storage"
```

### Task 2: Clustara 설정, 요청 계약, outbox 처리

**Files:**
- Create: `apps/api/src/modules/clustara/clustara.service.spec.ts`
- Create: `apps/api/src/modules/clustara/clustara.service.ts`
- Create: `apps/api/src/modules/clustara/clustara.controller.ts`
- Create: `apps/api/src/modules/clustara/clustara.module.ts`
- Modify: `apps/api/src/modules/settings/settings.service.ts`
- Modify: `apps/api/src/app.module.ts`

**Interfaces:**
- Produces: `ClustaraSettings`, `ClustaraAuthType`, `QueueDeliveryInput`, `ClustaraService.getSettings()`, `updateSettings()`, `testConnection()`, `queueDelivery()`, `queueAutomatic()`, `retryDelivery()`, `listDeliveries()`, `getDeliveriesForScan()`
- Consumes: `SettingsService.getRaw/set`, `PrismaService`, Node `http`/`https`

- [ ] **Step 1: Write failing tests for settings normalization and secret masking**

Test defaults for both paths, auth values `NONE`, `X_API_KEY`, `BEARER`, URL trimming, timeout range, max-attempt range, existing credential preservation on blank/masked updates, and `credentialConfigured` without returning `credential`.

Run: `pnpm --filter @jasca/api test -- clustara.service.spec.ts --runInBand`

Expected: FAIL because `ClustaraService` does not exist.

- [ ] **Step 2: Implement settings types and normalization**

Use these defaults:

```typescript
const DEFAULT_CLUSTARA_SETTINGS = {
  enabled: false,
  autoSend: false,
  baseUrl: '',
  scanPath: '/admin/k8s/security/scans/import',
  sbomPath: '/admin/k8s/security/sboms',
  authType: 'NONE' as const,
  credential: '',
  defaultClusterId: '',
  scanner: 'trivy',
  generator: 'syft',
  timeoutSeconds: 30,
  maxAttempts: 3,
  verifyTls: true,
};
```

Reject non-HTTP(S) Base URLs, paths not beginning with `/`, blank scanner/generator, and credentials missing for selected authenticated modes.

- [ ] **Step 3: Write failing tests for URL and auth headers**

Assert exact requests for:

```text
NONE      -> no Authorization or X-API-Key
X_API_KEY -> X-API-Key: secret
BEARER    -> Authorization: Bearer secret
```

Assert encoded query values and unchanged JSON body for both scan and SBOM endpoints.

Expected: FAIL because delivery execution is not implemented.

- [ ] **Step 4: Implement request construction and execution**

Use Node `URL`, `URLSearchParams`, `http.request`, and `https.request`. Pass `rejectUnauthorized: settings.verifyTls` only to HTTPS requests so the UI setting is per-request and never changes process-global TLS behavior. Store at most 1,000 response characters. Never include request headers or credential in stored errors.

- [ ] **Step 5: Write failing tests for digest derivation and retries**

Cover explicit digest, `Metadata.RepoDigests`, `Metadata.ImageID`, invalid short digest, no digest, 2xx success, 400 permanent failure, 408/429/500 retry, timeout retry, maximum-attempt failure, and duplicate queue requests.

- [ ] **Step 6: Implement DB outbox behavior**

Claim one due delivery with an atomic `updateMany` from `PENDING` to `SENDING`. Retry transient failures after 1 minute and then 5 minutes. Reset stale `SENDING` rows during module initialization and run a small `setInterval` worker without adding scheduler dependencies.

- [ ] **Step 7: Add guarded controller endpoints**

```text
GET  /clustara/settings
PUT  /clustara/settings
POST /clustara/test
GET  /clustara/deliveries
GET  /clustara/scans/:scanId/deliveries
POST /clustara/scans/:scanId/deliveries
POST /clustara/deliveries/:id/retry
```

Settings and global history require `SYSTEM_ADMIN` or `SECURITY_ADMIN`. Scan operations additionally allow `PROJECT_ADMIN` and `ORG_ADMIN` after `assertProjectAccess`.

- [ ] **Step 8: Run focused tests**

Run: `pnpm --filter @jasca/api test -- clustara.service.spec.ts --runInBand`

Expected: all Clustara service tests PASS.

- [ ] **Step 9: Commit**

```powershell
git add apps/api/src/modules/clustara apps/api/src/modules/settings/settings.service.ts apps/api/src/app.module.ts
git commit -m "feat: add Clustara delivery service"
```

### Task 3: Trivy 자동 전송과 Syft SBOM 영구 보존

**Files:**
- Create: `apps/api/src/modules/scans/services/trivy-sbom-artifact.spec.ts`
- Modify: `apps/api/src/modules/scans/services/trivy-scan.service.ts`
- Modify: `apps/api/src/modules/scans/scans.service.ts`
- Modify: `apps/api/src/modules/scans/scans.controller.ts`
- Modify: `apps/api/src/modules/scans/scans.module.ts`

**Interfaces:**
- Produces: `TrivyScanOutput { rawResult: unknown; generatedSbom?: string }`, `ScansService.persistCycloneDxArtifact(scanId, sbom, generatorVersion?)`
- Consumes: `ClustaraService.queueAutomatic(scanId)`, generated Prisma types

- [ ] **Step 1: Write failing tests for generated SBOM propagation**

Verify `runSyftThenTrivySbom` output reaches `scanUploadedFile` as `generatedSbom`, direct Trivy scans omit it, and execution evidence remains attached to `rawResult` only.

Expected: FAIL because `scanUploadedFile` returns raw JSON directly.

- [ ] **Step 2: Return an explicit Trivy scan output**

Extend `TrivyScanExecution` with optional `generatedSbom`, return it from Syft paths, and change the public method to return:

```typescript
export interface TrivyScanOutput {
  rawResult: any;
  generatedSbom?: string;
}
```

Keep temporary directory cleanup in `finally`; the SBOM string remains in memory until persisted.

- [ ] **Step 3: Write failing tests for durable artifact persistence**

Assert storage at `SCAN_RESULT_DIR/artifacts/{scanId}.cdx.json`, SHA256 calculation, DB upsert, replacement cleanup, and no DB row when file write fails.

- [ ] **Step 4: Implement artifact persistence**

Use `fs.promises.mkdir/writeFile/rename` with a temporary file followed by atomic rename. Parse enough CycloneDX metadata to record generator version when present; preserve the original JSON string byte-for-byte.

- [ ] **Step 5: Connect controller and automatic queueing**

The Trivy branch unwraps `rawResult`, calls the existing scan save, then persists `generatedSbom` after obtaining the scan ID. The shared `ScansService.uploadScan` completion path queues the Trivy delivery once; `persistCycloneDxArtifact` queues the SBOM delivery after durable storage. Queue failures are logged and do not change the scan response. Extend scan detail loading to include artifact metadata so the UI can decide whether SBOM transmission is available.

- [ ] **Step 6: Run scan and Clustara tests**

Run: `pnpm --filter @jasca/api test -- trivy-sbom-artifact.spec.ts clustara.service.spec.ts --runInBand`

Expected: both suites PASS.

- [ ] **Step 7: Commit**

```powershell
git add apps/api/src/modules/scans
git commit -m "feat: persist SBOMs for Clustara delivery"
```

### Task 4: 관리자 및 스캔 상세 UI

**Files:**
- Create: `apps/web/src/app/admin/clustara/page.tsx`
- Modify: `apps/web/src/app/admin/layout.tsx`
- Modify: `apps/web/src/lib/api-hooks.ts`
- Modify: `apps/web/src/app/dashboard/scans/[id]/page.tsx`

**Interfaces:**
- Produces: `ClustaraSettings`, `ClustaraDelivery`, settings/test/save/history/queue/retry React Query hooks
- Consumes: REST endpoints from Task 2 and existing `useScan`

- [ ] **Step 1: Add API types and hooks**

Add typed hooks with query keys `['clustara-settings']`, `['clustara-deliveries']`, and `['clustara-scan-deliveries', scanId]`. Successful mutations invalidate only related keys.

- [ ] **Step 2: Implement the admin settings page**

Provide editable Base URL, endpoint paths, auth selector, credential input, default query values, timeout, attempts, TLS, enabled and auto-send controls. Keep credential blank after load and show `등록됨`. Disable connection test and save while requests are running. Render status, HTTP code, attempts, timestamps, concise error, and retry action.

- [ ] **Step 3: Add navigation**

Add `Clustara 연동` under the system section next to Vuln Portal using an existing Lucide network/link icon.

- [ ] **Step 4: Add the scan-detail delivery panel**

Show only for Trivy-attributed scans. Pre-fill cluster ID and scanner from settings and digest from the scan. Validate `/^sha256:[a-f0-9]{64}$/i`. Allow separate `TRIVY` and `SBOM` send actions when an artifact exists, and display delivery state with manual retry.

- [ ] **Step 5: Type-check and build**

Run: `pnpm --filter @jasca/web exec tsc --noEmit`

Expected: no TypeScript errors.

Run: `pnpm --filter @jasca/web build`

Expected: build succeeds; known Windows standalone symlink warnings may remain.

- [ ] **Step 6: Commit**

```powershell
git add apps/web/src/app/admin/clustara apps/web/src/app/admin/layout.tsx apps/web/src/lib/api-hooks.ts apps/web/src/app/dashboard/scans/[id]/page.tsx
git commit -m "feat: add Clustara integration UI"
```

### Task 5: 폐쇄망 배포 설정과 전체 검증

**Files:**
- Modify: `docker/monolith/deploy-existing-layout.env.example`
- Modify: `docker/monolith/deploy-existing-layout.sh`
- Modify: `docker/monolith/README-OFFLINE.md`
- Modify: `k8s/monolith/configmap.yaml`
- Modify: `k8s/monolith/deployment.yaml`
- Modify: `docs/Kubernetes_Deployment_Guide_kr.md`

**Interfaces:**
- Produces: optional `NODE_EXTRA_CA_CERTS` mount/config examples and Clustara secret injection guidance
- Consumes: existing monolith Docker and Kubernetes layouts

- [ ] **Step 1: Add closed-network CA configuration**

Document and pass through optional `NODE_EXTRA_CA_CERTS=/app/jasca-ca/internal-ca.crt`. Add read-only host file/secret mount examples without enabling insecure TLS by default. Keep API credentials out of ConfigMap and use Docker env/Kubernetes Secret examples.

- [ ] **Step 2: Run API verification**

Run: `pnpm --filter @jasca/api exec tsc --noEmit`

Run: `pnpm --filter @jasca/api test -- --runInBand`

Run: `pnpm --filter @jasca/api build`

Expected: all commands succeed.

- [ ] **Step 3: Run Prisma migration smoke test**

Start the local database stack, apply migrations to a disposable/local database, and verify both new tables and indexes exist. Do not alter production or closed-network data.

- [ ] **Step 4: Browser QA**

Run JASCA locally and verify:

1. Admin Clustara settings load, save, mask credential, and survive refresh.
2. All three auth modes produce the expected request against a local mock HTTP endpoint.
3. Custom paths and query values appear exactly at the mock endpoint.
4. A Trivy scan succeeds while Clustara is unavailable and records a failed delivery.
5. Retry succeeds after the mock endpoint returns 200.
6. The scan detail rejects an invalid digest before network activity.
7. A Syft-assisted scan retains and sends its CycloneDX artifact after temp cleanup.

- [ ] **Step 5: Build and inspect linux/amd64 image**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\script\build-offline-bundle.ps1 -ImageName 'jasca-offline:latest' -BundleName 'jasca-offline-clustara-amd64' -OutputDir 'dist\offline-bundle' -Platform 'linux/amd64'
docker image inspect jasca-offline:latest --format '{{.Os}}/{{.Architecture}}'
```

Expected: `linux/amd64` and offline bundle creation succeeds.

- [ ] **Step 6: Final diff and secret audit**

Run: `git diff --check`

Run: `rg -n "X-API-Key:|Authorization: Bearer|CLUSTARA.*(KEY|TOKEN).*=" apps docker k8s docs -g '!*.spec.ts'`

Expected: no committed real credential and no whitespace errors.

- [ ] **Step 7: Commit deployment documentation**

```powershell
git add docker/monolith k8s/monolith docs/Kubernetes_Deployment_Guide_kr.md
git commit -m "docs: add Clustara offline deployment guidance"
```
