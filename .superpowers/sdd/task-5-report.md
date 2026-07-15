# Task 5 - AI Web Background UX

## Implemented

- `POST /api/ai/jobs` asynchronous submission while preserving the existing `useAiExecution` return shape.
- Persisted only AI result history and serializable pending job metadata; removed persisted/runtime `AbortController` state.
- Global pending-job resumer polls active jobs after navigation or application re-entry without redirecting the user.
- Added `/dashboard/ai-results/[id]` with status, result, error, cancel, retry, and export controls.
- Kept completion notifications server-owned; the web client does not create duplicate notifications.
- PDF/DOCX export defaults to summary scope (top 20), confirms full export, honors `Content-Disposition`, rejects empty/JSON payloads, and shows visible success/error/retry feedback.
- New and touched AI UI strings are valid Korean UTF-8.

## Verification

- `node --test --experimental-strip-types apps/web/src/lib/ai-job-utils.test.ts`: 7 passed, 0 failed.
- `pnpm --filter @jasca/web exec tsc --noEmit`: passed.
- `pnpm --filter @jasca/web build`: passed and generated `/dashboard/ai-results/[id]`.
- Windows standalone trace emitted existing symlink `EPERM` warnings after successful build; compile, type validation, and static generation completed with exit code 0.
