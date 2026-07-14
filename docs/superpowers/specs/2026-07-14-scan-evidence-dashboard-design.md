# Scan Evidence and Dashboard Design

## Goal

Make scanner execution evidence trustworthy, keep Checkov options easy to review, and make dashboard numbers use one explicit reporting period.

## Scope

- Semgrep stores the redacted command it executed and the resolved rule configuration count in `JascaScanEvidence`.
- The scan-detail command panel presents Semgrep evidence using the existing command-panel convention.
- The Checkov options panel retains its right-side placement, adds a compact selected-framework summary, and keeps framework cards readable at desktop and mobile widths.
- The dashboard gets one reporting period selector: 7 days, 30 days, 90 days, or all time. The period drives scanner cards and scan-derived chart summaries. Existing vulnerability overview APIs remain unchanged until the API supports a matching period filter.

## Non-goals

- Do not download Semgrep rules or Checkov modules at scan time.
- Do not add a date-picker dependency or a custom arbitrary-range API in this change.
- Do not split Semgrep into a new dashboard scanner category; it remains under SAST/SARIF to preserve existing reporting semantics.

## Data Flow

Semgrep builds its argument list once, runs it, and writes a display-safe `command` value into scan evidence. The scan-detail page already renders evidence commands, so no separate data field or endpoint is necessary.

The dashboard filters loaded scan rows by the chosen period before generating scanner summaries. The selected period is also supplied to the existing trend hook. This makes all scan-derived numbers comparable without changing the backend statistics contract.

## Error Handling and UX

- Semgrep evidence must not reveal upload paths or credentials; only the existing redacted command format is stored.
- A Semgrep run that reuses an incremental baseline records a descriptive command instead of pretending a process was executed.
- Checkov displays the selected framework count and names, and uses the same option-panel hierarchy as the other scanners.
- The period selector is visible near dashboard-level operational summaries, with an explicit `전체 기간` option.

## Verification

- Unit tests assert Semgrep stores a display-safe command for normal and incremental-reuse scans.
- Existing Semgrep and Checkov tests remain green.
- Build the API and web application.
- Build a Docker image, run JASCA locally, and verify Semgrep detail evidence, Checkov layout and interactions, dashboard period controls, desktop/mobile rendering, and browser console health.
