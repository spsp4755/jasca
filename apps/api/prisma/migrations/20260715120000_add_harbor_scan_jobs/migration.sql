CREATE TYPE "HarborScanJobStatus" AS ENUM ('RUNNING', 'COMPLETED', 'FAILED');

CREATE TABLE "HarborScanJob" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "imageRef" TEXT NOT NULL,
    "imageDigest" TEXT NOT NULL,
    "tag" TEXT,
    "trigger" TEXT NOT NULL,
    "status" "HarborScanJobStatus" NOT NULL,
    "scanResultId" TEXT,
    "error" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "HarborScanJob_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "HarborScanJob_projectId_imageDigest_key"
    ON "HarborScanJob"("projectId", "imageDigest");

CREATE INDEX "HarborScanJob_status_startedAt_idx"
    ON "HarborScanJob"("status", "startedAt");

CREATE INDEX "HarborScanJob_scanResultId_idx"
    ON "HarborScanJob"("scanResultId");

ALTER TABLE "HarborScanJob"
    ADD CONSTRAINT "HarborScanJob_projectId_fkey"
    FOREIGN KEY ("projectId") REFERENCES "Project"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "HarborScanJob"
    ADD CONSTRAINT "HarborScanJob_scanResultId_fkey"
    FOREIGN KEY ("scanResultId") REFERENCES "ScanResult"("id")
    ON DELETE SET NULL ON UPDATE CASCADE;
