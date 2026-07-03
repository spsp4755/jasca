# JASCA ZAP Integration Design

## Goal

Add OWASP ZAP DAST scanning to JASCA while keeping ZAP isolated from the main JASCA runtime. Users should start, monitor, and review ZAP scans entirely inside JASCA. ZAP itself is an execution engine, not a user-facing console.

## Operating Model

ZAP will run as a separate scanner service.

- Docker phase: run `jasca-offline` and `zap-scanner` as separate containers on the same closed-network host or Docker network.
- Kubernetes phase: run JASCA and ZAP as separate Deployments, with a Service exposing ZAP only to JASCA.
- JASCA owns scan configuration, permissions, state, result normalization, dashboard aggregation, alerts, exports, and audit logs.
- ZAP owns crawling, passive scan, optional active scan, and raw alert generation.

This keeps ZAP CPU, memory, network traffic, and scanner failures isolated from JASCA API, PostgreSQL, Redis, and Web.

## Recommended Architecture

```text
User
  -> JASCA Web
  -> JASCA API
  -> ZAP Scanner Service
       -> Target web application
  -> JASCA stores normalized ZAP result
  -> JASCA dashboards, scan details, alerts, reports
```

JASCA should never require users to open the ZAP UI. The ZAP API URL and API key are administrator-managed settings.

## Phase 1 Scope

Phase 1 focuses on safe, useful web scanning.

- Add administrator ZAP settings.
- Add connection test for the ZAP service.
- Add `ZAP Web Scan` to the scan creation screen.
- Support URL target input.
- Support Baseline scan mode.
- Support Spider + Passive Scan workflow.
- Store raw ZAP JSON for audit and troubleshooting.
- Normalize ZAP alerts into JASCA scan result records.
- Display ZAP-specific result list and detail views.
- Generate notifications for configured ZAP risk thresholds.
- Keep Active Scan disabled by default.
- Allow Active Scan only when an administrator explicitly enables it.

Out of scope for Phase 1:

- Authenticated browser session crawling.
- AJAX spider tuning.
- Full policy editor.
- Distributed scanner pool.
- CI webhook automation.
- Automatic remediation advice generation beyond ZAP-provided solution/reference fields.

## Admin Settings

Add a ZAP settings section under administrator integration or scanner settings.

Required settings:

- `enabled`: whether ZAP scanning is available.
- `zapBaseUrl`: internal ZAP API endpoint, for example `http://zap-scanner:8080`.
- `apiKey`: ZAP API key.
- `connectTimeoutSeconds`: connection timeout for ZAP API calls.
- `maxScanDurationMinutes`: hard timeout per scan.
- `maxConcurrentScans`: initial default should be `1`.
- `allowBaselineScan`: enabled by default.
- `allowActiveScan`: disabled by default.
- `allowedTargetPatterns`: required allowlist of hostnames, domains, or CIDR-like patterns.
- `blockedTargetPatterns`: explicit denylist.
- `defaultRiskThresholdForNotification`: default `High`.

Security rules:

- JASCA must reject ZAP scans when the target URL does not match the allowlist.
- JASCA must reject private or sensitive destinations unless they are explicitly allowed.
- JASCA must not expose the ZAP API key to the browser.
- Active Scan must require both admin enablement and per-scan user selection.

## User Scan Flow

The scan creation screen should provide a scanner selector with at least:

- Trivy file/image scan
- Checkov IaC/CI scan
- ZAP web scan

For ZAP web scan, users provide:

- Target URL
- Project
- Scan mode: Baseline or Passive workflow in Phase 1
- Optional context label
- Optional notification threshold

If Active Scan is disabled by admin settings, the option is hidden or disabled with a clear explanation.

## ZAP Execution Flow

Phase 1 baseline workflow:

1. Validate target URL against admin allowlist/denylist.
2. Create a JASCA scan operation with status `RUNNING`.
3. Call ZAP API to access the target URL.
4. Run spider or baseline workflow.
5. Poll ZAP status until complete or timeout.
6. Fetch alerts as JSON.
7. Store raw JSON in JASCA.
8. Normalize alerts into JASCA findings.
9. Mark scan `COMPLETED`, `FAILED`, or `CANCELLED`.
10. Trigger notifications based on risk threshold.

Cancellation should call the relevant ZAP stop endpoint when possible, then mark the JASCA operation as cancelled.

## Result Model

ZAP alerts should be normalized into JASCA findings while preserving ZAP-specific fields.

Important fields:

- `alert`
- `risk`
- `confidence`
- `url`
- `method`
- `parameter`
- `evidence`
- `attack`
- `description`
- `solution`
- `reference`
- `cweid`
- `wascid`
- `instances`

Risk mapping:

- ZAP `High` -> JASCA `HIGH`
- ZAP `Medium` -> JASCA `MEDIUM`
- ZAP `Low` -> JASCA `LOW`
- ZAP `Informational` -> JASCA `UNKNOWN` or scanner-specific informational bucket

The UI should label these as web findings, not package vulnerabilities.

## Scan List UX

The scan result list should show ZAP results differently from Trivy and Checkov.

Recommended columns:

- Target URL
- Project
- Scanner: `ZAP`
- Status
- Risk summary: `High / Medium / Low / Info`
- Scan mode
- Duration
- Scan date

Filtering should support scanner type `ZAP` and risk level.

## Scan Detail UX

ZAP detail pages should be scanner-specific.

Recommended sections:

- Summary: target URL, mode, status, duration, total alerts, highest risk.
- Risk distribution: High, Medium, Low, Informational.
- Alerts table: alert name, risk, confidence, URL count, parameter, evidence snippet.
- Alert detail drawer/page: affected URLs, evidence, request method, parameter, description, solution, references, CWE/WASC.
- Execution evidence: ZAP service URL, scan mode, timeout, command/API workflow summary.
- Raw result download.

Do not display Trivy-specific labels such as package count, image layer, fixed version, or license tab unless the data exists.

## Dashboard UX

Dashboards should aggregate ZAP findings but allow scanner separation.

Add or extend:

- Scanner filter: All / Trivy / Checkov / ZAP.
- Web risk summary card for ZAP findings.
- Recent ZAP scans.
- Projects with highest web risk.
- High risk web findings requiring action.
- ZAP scan failures or timeouts.

Avoid mixing ZAP web alerts into package vulnerability totals without a scanner filter, because the meanings differ.

## Error Handling

JASCA should produce clear user-facing errors for:

- ZAP disabled by admin.
- ZAP service unreachable.
- Invalid API key.
- Target URL blocked by policy.
- Target URL not reachable from ZAP.
- Scan timed out.
- Active Scan not allowed.
- ZAP returned malformed JSON.

All failures should keep a scan operation record for auditability.

## Docker Deployment

The closed-network Docker deployment should use a separate ZAP image asset.

Recommended assets:

- `jasca-offline-vX.Y.Z-bundle.tar.gz`
- `zap-scanner-vX.Y.Z.tar.gz` or included ZAP image tar inside the bundle
- Docker run or compose-style script that starts both containers on a private network

Example topology:

```text
docker network: jasca-net
container: jasca
container: zap-scanner
JASCA_ZAP_BASE_URL=http://zap-scanner:8080
```

ZAP should not be exposed publicly unless there is a deliberate admin reason.

## Kubernetes Deployment

Kubernetes should use separate Deployments.

Recommended resources:

- `Deployment/jasca`
- `Service/jasca`
- `Deployment/zap-scanner`
- `Service/zap-scanner`
- `Secret/zap-api-key`
- `ConfigMap/jasca-zap-settings`
- `NetworkPolicy` allowing JASCA to call ZAP
- `NetworkPolicy` restricting ZAP egress to approved target networks where possible

Resource limits should be explicit for ZAP. Initial defaults should be conservative.

## Testing Strategy

Unit tests:

- ZAP alert parser maps risk and fields correctly.
- Target allowlist/denylist validation works.
- ZAP settings defaults are safe.

Integration tests:

- Mock ZAP API returns alerts and JASCA stores them.
- ZAP unreachable returns a clear failure.
- Cancellation marks operation as cancelled.

Manual local tests:

- Run JASCA and ZAP containers.
- Scan a local intentionally vulnerable web target.
- Verify list, detail, dashboard, alert, raw JSON download.

Closed-network tests:

- Load both image tar files.
- Start both containers without internet.
- Verify ZAP service connection test.
- Verify target allowlist blocks unauthorized URLs.
- Verify one baseline scan completes and appears in JASCA.

## Open Decisions Before Implementation

- Which ZAP image strategy to use for closed-network release: official image tar as separate asset or custom `jasca-zap-scanner` image.
- Whether Phase 1 should use ZAP API directly or wrap ZAP with a small scanner worker service.
- Whether Active Scan appears in the UI as disabled or hidden when admin settings disallow it.

Recommended decisions:

- Use a custom `jasca-zap-scanner` image later if we need curated add-ons or scripts, but start with official ZAP image compatibility.
- Let JASCA API call ZAP API directly in Phase 1 to reduce moving parts.
- Show Active Scan as disabled with an explanation, so users understand why it is unavailable.
