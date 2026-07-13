# ZAP Safe Passive Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Present and enforce JASCA ZAP as a passive spider scan, document its closed-network safety boundary, and restore readable Checkov scan options.

**Architecture:** Keep the existing ZAP client and scan workflow. Constrain the shared `ZapScanService` input boundary so all browser and API callers reject `active`; simplify the existing scan form rather than adding configuration. Repair only the corrupted literals in the existing page.

**Tech Stack:** NestJS, Jest, Next.js, React, TypeScript, Docker.

## Global Constraints

- No new dependencies or schema migrations.
- Active ZAP attack APIs remain out of scope.
- Preserve `baseline` and `passive` API compatibility.
- Closed-network Docker deployment must not publish ZAP port 8080.

---

### Task 1: Enforce passive-only ZAP scan requests

**Files:**
- Modify: `apps/api/src/modules/scans/services/zap-scan.service.ts`
- Modify: `apps/api/src/modules/scans/services/zap-scan.service.spec.ts`

- [ ] Write a failing test calling `scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'active' })`, expecting `Passive Spider Scan` and no `zapClient.getVersion` call.
- [ ] Run `apps/api/node_modules/.bin/jest.CMD src/modules/scans/services/zap-scan.service.spec.ts --runInBand`; expect the new test to fail because active currently enters the workflow.
- [ ] Add an early `active` rejection in `scanUrl()` before the ZAP client is used.
- [ ] Rerun the focused Jest test; expect it to pass.
- [ ] Commit the backend change with `fix: restrict ZAP scans to passive mode`.

### Task 2: Simplify the ZAP and Checkov scan options UI

**Files:**
- Modify: `apps/web/src/app/dashboard/scans/new/page.tsx`

- [ ] Remove the ZAP mode selector and submit `scanMode: 'passive'`.
- [ ] Add a Passive Spider Scan description stating that it spiders approved URLs and collects passive alerts only.
- [ ] Replace visible corrupted Checkov Korean literals with valid UTF-8 Korean descriptions; preserve framework controls and request values.
- [ ] Run `apps/web/node_modules/.bin/next.CMD build`; expect `/dashboard/scans/new` in the output.
- [ ] Commit with `fix: clarify ZAP passive scanning options`.

### Task 3: Add closed-network ZAP safety guidance

**Files:**
- Modify: `docker/monolith/README-OFFLINE.md`
- Modify: `k8s/zap-scanner/README_KO.md`

- [ ] Add the four-item safety checklist: approved non-production target, no host/Ingress ZAP API exposure, least-privilege short-lived test session, and egress restricted to approved targets.
- [ ] Run `bash -n docker/monolith/deploy-existing-layout.sh`; expect exit code 0.
- [ ] Commit with `docs: add safe ZAP deployment guidance`.

### Task 4: Full verification and release preparation

**Files:**
- Verify: `apps/api`, `apps/web`, `docker/monolith/Dockerfile`

- [ ] Run all API tests with `apps/api/node_modules/.bin/jest.CMD --runInBand`.
- [ ] Build API with `apps/api/node_modules/.bin/nest.CMD build` and web with `apps/web/node_modules/.bin/next.CMD build`.
- [ ] Build `linux/amd64` Docker image tagged `jasca-offline:zap-safe-test`, start it on isolated ports, and verify it serves the login page.
- [ ] On successful verification, push `main`, tag `v0.3.9`, build the offline AMD64 bundle, and publish the release assets.
