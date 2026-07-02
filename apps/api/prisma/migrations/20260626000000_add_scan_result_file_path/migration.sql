-- Add persisted raw result file path to ScanResult
ALTER TABLE "ScanResult" ADD COLUMN IF NOT EXISTS "resultFilePath" TEXT;
