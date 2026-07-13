# ZAP 안전 운영 프로필 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 관리자 대상 프로필을 통해 Passive ZAP 스캔의 URL 범위와 실행 시간을 통제하고 연결 상태를 확인한다.

**Architecture:** 기존 `zap` 설정 객체에 `targetProfiles` 배열을 추가하고 `ZapPolicyService`에서 전역 정책과 선택 프로필을 함께 검증한다. `ZapScanService`는 프로필 이름과 더 짧은 실행 시간을 evidence에 기록하며, 연결 테스트는 기존 ZAP client의 version API를 재사용한다.

**Tech Stack:** NestJS, Jest, Next.js, React Query, 기존 ZAP REST client

## Global Constraints

- ZAP Active Scan은 계속 거부한다.
- 인증 값은 DB, evidence, 로그에 저장하지 않는다.
- 새 의존성이나 DB 스키마 변경을 추가하지 않는다.
- 대상 범위는 기존 `http`/`https` wildcard 정책과 전역 정책을 모두 통과해야 한다.

---

### Task 1: Profile policy and connection-test API

**Files:**
- Modify: `apps/api/src/modules/scans/services/zap-policy.service.ts`
- Modify: `apps/api/src/modules/scans/services/zap-scan.service.ts`
- Modify: `apps/api/src/modules/scans/scans.controller.ts`
- Modify: `apps/api/src/modules/scans/services/zap-scan.service.spec.ts`
- Test: `apps/api/src/modules/scans/services/zap-policy.service.spec.ts`

**Interfaces:**
- Produces `ZapTargetProfile` with `id`, `name`, `enabled`, allow/blocked patterns, `maxScanDurationMinutes`, and notification threshold.
- Produces `validateTargetUrl(targetUrl, settings, profileId)` and `testConnection()`.

- [ ] **Step 1: Write failing policy tests**

```ts
expect(() => service.validateTargetUrl('https://outside.internal', settings, 'internal-app'))
  .toThrow('not allowed by the selected profile');
expect(() => service.validateTargetUrl('https://app.internal', settings, 'disabled-profile'))
  .toThrow('selected profile is disabled');
```

- [ ] **Step 2: Run the policy tests and verify they fail because the profile argument is not implemented.**

Run: `apps/api/node_modules/.bin/jest.cmd src/modules/scans/services/zap-policy.service.spec.ts --runInBand`

- [ ] **Step 3: Add the minimal profile validation and effective timeout selection.**

```ts
const profile = settings.targetProfiles.find((item) => item.id === profileId && item.enabled);
if (!profile) throw new BadRequestException('ZAP target profile is unavailable.');
if (!profile.allowedTargetPatterns.some((pattern) => this.matchesPattern(parsed, pattern))) {
  throw new BadRequestException('ZAP target URL is not allowed by the selected profile.');
}
```

- [ ] **Step 4: Add failing ZAP service tests for evidence profile metadata and version-only connection testing, then implement the smallest service/controller changes.**

```ts
await expect(service.testConnection()).resolves.toEqual({ connected: true, version: '2.15.0' });
expect(result.Metadata.JascaScanEvidence.targetProfile).toEqual({ id: 'internal-app', name: 'Internal App' });
```

- [ ] **Step 5: Run focused tests and commit.**

Run: `apps/api/node_modules/.bin/jest.cmd src/modules/scans/services/zap-policy.service.spec.ts src/modules/scans/services/zap-scan.service.spec.ts --runInBand`

### Task 2: Admin and scan-form UI

**Files:**
- Modify: `apps/web/src/lib/api-hooks.ts`
- Modify: `apps/web/src/app/admin/trivy-settings/page.tsx`
- Modify: `apps/web/src/app/dashboard/scans/new/page.tsx`

**Interfaces:**
- Consumes `ZapTargetProfile` returned as part of `ZapSettings`.
- Sends `targetProfileId` in the existing `POST /api/scans/scan/zap` request.

- [ ] **Step 1: Add the failing UI contract by compiling against `targetProfiles` and `testZapConnection`.**

Run: `apps/web/node_modules/.bin/next.cmd build`

- [ ] **Step 2: Add profile CRUD rows to the existing ZAP admin settings card and a Version-only connection-test button.**

```tsx
<button type="button" onClick={handleTestZapConnection}>연결 테스트</button>
```

- [ ] **Step 3: Require one enabled profile selection before a user starts ZAP scan and show only its name/description.**

```tsx
<select value={zapTargetProfileId} onChange={(event) => setZapTargetProfileId(event.target.value)}>
  <option value="">대상 프로필을 선택하세요</option>
</select>
```

- [ ] **Step 4: Build the web application and commit.**

Run: `apps/web/node_modules/.bin/next.cmd build`

### Task 3: Documentation and end-to-end verification

**Files:**
- Modify: `docker/monolith/README-OFFLINE.md`
- Modify: `k8s/zap-scanner/README_KO.md`

- [ ] **Step 1: Document profile setup, version-only connection test, and authentication non-storage.**
- [ ] **Step 2: Run API tests, API build, web build, and AMD64 Docker build.**

Run: `apps/api/node_modules/.bin/jest.cmd --runInBand`, `apps/api/node_modules/.bin/nest.cmd build`, `apps/web/node_modules/.bin/next.cmd build`, `docker build --platform linux/amd64 -f docker/monolith/Dockerfile -t jasca-offline:zap-profiles-test .`

- [ ] **Step 3: Start an isolated container and verify admin profile selection, connection-test failure presentation, and passive-only scan-form behavior in the browser.**
- [ ] **Step 4: Commit documentation and verification-ready implementation.**
