# ZAP Safe Passive Scan Design

## Goal

Make the existing JASCA ZAP workflow accurately represent its implemented passive behavior, make the administrator-visible safety limits clear, and repair the broken Checkov option panel without adding a second scanning platform or new dependencies.

## Scope

- Remove the user-selectable Active Scan mode. The existing backend never invokes ZAP's active scan API, so exposing it is misleading.
- Rename the user-facing ZAP mode to Passive Spider Scan and retain the current spider plus passive-alert collection behavior.
- Preserve administrator controls: enablement, HTTP/S target validation, allowlist, blocklist, timeout, single-concurrency default, and ZAP API key masking.
- Add concise safety guidance in the scan form and offline deployment guide: use non-production targets and least-privileged test credentials; prevent ZAP API exposure; constrain network egress.
- Repair Checkov option content that renders as mojibake by replacing corrupted Korean literals with UTF-8 Korean text in the affected scan screen.

## Explicit Non-Goals

- Do not implement ZAP active attack APIs, authentication scripts, ZAP Context management, request-rate controls, depth limits, or a new credential vault.
- Do not change the existing database schema or add a dependency.
- Do not change scanner execution semantics beyond rejecting the obsolete `active` API value.

## Backend Behavior

`ZapScanOptions.scanMode` accepts only `baseline` and `passive` for compatibility with existing API clients. Both map to the existing spider and passive-alert behavior. The backend rejects `active` before contacting ZAP, so direct API callers cannot bypass the UI restriction.

## UI Behavior

The ZAP form contains a single read-only mode description, not a mode selector. It clearly states that the scan spiders the approved URL and collects passive alerts only. Authentication remains optional, but the form warns that only a scoped test account should be used.

The Checkov panel keeps its current controls and framework descriptions, but every displayed Korean string is valid UTF-8 and readable.

## Deployment Safety

The existing ZAP container remains private to the JASCA Docker network. Documentation states that its API must not be host-published and Kubernetes operators should constrain ingress to JASCA and egress to approved target networks using NetworkPolicy or equivalent firewall controls.

## Verification

- Unit test: an `active` ZAP request is rejected before any client call.
- Unit test: baseline/passive scans still use the existing spider route.
- UI build verifies the removed mode selector and corrected Checkov strings compile.
- Docker image build and isolated runtime smoke test verify the application starts with the existing data migration path.
