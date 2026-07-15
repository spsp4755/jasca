# Task 3 Report: Harbor Admin and Manual Scan UI

## Implemented

- Added `/admin/harbor` with Harbor URL, Robot Account, masked Robot Token and Webhook Secret fields, allowed Harbor projects, default JASCA project, auto-scan toggle, save action, and connection test.
- Added Harbor navigation to the admin sidebar.
- Added typed Harbor React Query hooks for settings, connection testing, project/repository/artifact browsing, and `POST /harbor/scan`.
- Added the Harbor scanner to the manual scan page. It follows JASCA project -> Harbor project -> repository -> immutable digest, treats tags as supplementary metadata, and does not render a file upload target.
- Documented the exact Push Artifact webhook endpoint and `Authorization: Bearer <Webhook Secret>` requirement; the page explicitly warns against Harbor HMAC signature headers.

## Verification

- `npm.cmd run build` in `apps/web` exited 0.
- The build generated `/admin/harbor` and `/dashboard/scans/new` successfully.
- The build emitted pre-existing Windows standalone-output symlink warnings (`EPERM`) and stale Browserslist data warnings, but completed successfully.
- `git diff --check` exited 0.

## Scope

- Staged task files are limited to the four assigned web paths and this report.
- Existing concurrent worktree changes were not modified or staged.
