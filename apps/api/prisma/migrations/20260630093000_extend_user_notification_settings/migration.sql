-- Add detailed per-user notification controls used by dashboard/profile UI.
ALTER TABLE "UserNotificationSetting"
ADD COLUMN IF NOT EXISTS "scanComplete" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN IF NOT EXISTS "criticalVulns" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN IF NOT EXISTS "highVulns" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN IF NOT EXISTS "policyViolations" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN IF NOT EXISTS "exceptionAlerts" BOOLEAN NOT NULL DEFAULT true;
