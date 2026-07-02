-- Add vuln-portal pull integration storage without changing existing scan data.
CREATE TYPE "VulnPortalIntelType" AS ENUM ('VULNERABILITY', 'KEV', 'EOL');
CREATE TYPE "VulnPortalSyncStatus" AS ENUM ('SUCCESS', 'FAILED', 'RUNNING');

CREATE TABLE "VulnPortalIntel" (
    "id" TEXT NOT NULL,
    "type" "VulnPortalIntelType" NOT NULL,
    "externalId" TEXT NOT NULL,
    "cveId" TEXT,
    "title" TEXT,
    "description" TEXT,
    "severity" "Severity" NOT NULL DEFAULT 'UNKNOWN',
    "vendor" TEXT,
    "product" TEXT,
    "cvssScore" DOUBLE PRECISION,
    "cvssVector" TEXT,
    "epssScore" DOUBLE PRECISION,
    "isKev" BOOLEAN NOT NULL DEFAULT false,
    "publishedAt" TIMESTAMP(3),
    "modifiedAt" TIMESTAMP(3),
    "dueDate" TIMESTAMP(3),
    "eolDate" TIMESTAMP(3),
    "raw" JSONB NOT NULL,
    "lastSyncedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "VulnPortalIntel_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "VulnPortalSyncLog" (
    "id" TEXT NOT NULL,
    "status" "VulnPortalSyncStatus" NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),
    "vulnerabilities" INTEGER NOT NULL DEFAULT 0,
    "kev" INTEGER NOT NULL DEFAULT 0,
    "eol" INTEGER NOT NULL DEFAULT 0,
    "message" TEXT,
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VulnPortalSyncLog_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "VulnPortalIntel_type_externalId_key" ON "VulnPortalIntel"("type", "externalId");
CREATE INDEX "VulnPortalIntel_type_idx" ON "VulnPortalIntel"("type");
CREATE INDEX "VulnPortalIntel_cveId_idx" ON "VulnPortalIntel"("cveId");
CREATE INDEX "VulnPortalIntel_severity_idx" ON "VulnPortalIntel"("severity");
CREATE INDEX "VulnPortalIntel_isKev_idx" ON "VulnPortalIntel"("isKev");
CREATE INDEX "VulnPortalIntel_vendor_idx" ON "VulnPortalIntel"("vendor");
CREATE INDEX "VulnPortalIntel_product_idx" ON "VulnPortalIntel"("product");
CREATE INDEX "VulnPortalIntel_lastSyncedAt_idx" ON "VulnPortalIntel"("lastSyncedAt");
CREATE INDEX "VulnPortalSyncLog_status_idx" ON "VulnPortalSyncLog"("status");
CREATE INDEX "VulnPortalSyncLog_startedAt_idx" ON "VulnPortalSyncLog"("startedAt");
