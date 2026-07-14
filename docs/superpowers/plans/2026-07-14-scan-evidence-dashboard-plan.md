# Scan Evidence and Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record Semgrep execution evidence and align Checkov and dashboard reporting UX without adding online dependencies.

**Architecture:** Reuse the existing `Metadata.JascaScanEvidence` object for Semgrep command metadata. Reuse `scannerSummariesToList` for dashboard aggregation after an in-memory period filter, and retain the existing Checkov right-side option panel.

**Tech Stack:** NestJS, Jest, Next.js 14, React, Tailwind CSS, Docker.

## Global Constraints

- The product remains air-gapped: no external rule/module download at scan time.
- No new runtime dependencies.
- Do not alter scanner result attribution or existing scan result URLs.

---

### Task 1: Semgrep execution evidence

**Files:**
- Modify: `apps/api/src/modules/scans/services/semgrep-scan.service.ts`
- Modify: `apps/api/src/modules/scans/services/semgrep-scan.service.spec.ts`

**Interfaces:**
- Produces: `Metadata.JascaScanEvidence.command: string` for Semgrep scan results.

- [ ] **Step 1: Write failing tests**

Add tests that execute the argument/evidence construction path and assert that a normal run stores `semgrep scan --sarif`, while an incremental baseline reuse stores `semgrep scan (incremental baseline reused)`.

- [ ] **Step 2: Run the focused test**

Run: `apps/api/node_modules/.bin/jest.cmd --runInBand src/modules/scans/services/semgrep-scan.service.spec.ts`

Expected: failure because `command` is absent from `JascaScanEvidence`.

- [ ] **Step 3: Implement the smallest change**

Create the display command from the same `args` passed to `runSemgrep`, replace temporary absolute paths with stable placeholders, and assign it to `JascaScanEvidence.command`. Set the explicit incremental-reuse command when no child process runs.

- [ ] **Step 4: Re-run focused tests**

Run the same Jest command and expect all Semgrep service tests to pass.

### Task 2: Checkov option clarity

**Files:**
- Modify: `apps/web/src/app/dashboard/scans/new/page.tsx`

**Interfaces:**
- Produces: a selected-framework summary directly above the Checkov framework cards.

- [ ] **Step 1: Add the compact selection summary**

Show `전체 프레임워크 자동 감지` when none are selected. Otherwise show the selected count and the selected framework labels. Keep cards in the existing two-column desktop layout and one-column mobile layout.

- [ ] **Step 2: Build the web application**

Run: `pnpm --filter @jasca/web build`

Expected: exit code 0.

### Task 3: Dashboard reporting period consistency

**Files:**
- Modify: `apps/web/src/app/dashboard/page.tsx`
- Modify: `apps/web/src/lib/scanner-summary.ts`
- Create: `apps/web/src/lib/scanner-summary.test.ts`

**Interfaces:**
- Produces: `filterScansByPeriod(scans, period, now?)` returning scans whose completion/start/create date is within the selected period.

- [ ] **Step 1: Write failing unit tests**

Add tests asserting 7-day filtering includes a seven-day-old completed scan, excludes an eight-day-old scan, and `all` retains both scans.

- [ ] **Step 2: Run the focused test**

Run: `apps/web/node_modules/.bin/jest.cmd scanner-summary.test.ts`

Expected: failure because `filterScansByPeriod` does not exist.

- [ ] **Step 3: Implement the helper and selector**

Export `filterScansByPeriod`, select `7 | 30 | 90 | 'all'` on the dashboard, pass numeric periods into the existing trend query, and build scanner cards from the filtered list. Keep the vulnerability overview cards explicitly labeled as current totals because their backend API has no period parameter.

- [ ] **Step 4: Verify builds and UI**

Run API/web builds, build Docker, then verify the three target flows in a browser at desktop and mobile widths.
