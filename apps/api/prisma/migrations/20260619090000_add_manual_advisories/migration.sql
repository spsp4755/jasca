-- CreateTable
CREATE TABLE "ManualAdvisory" (
    "id" TEXT NOT NULL,
    "advisoryId" TEXT NOT NULL,
    "cveId" TEXT,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "severity" "Severity" NOT NULL,
    "packageName" TEXT NOT NULL,
    "affectedVersionRange" TEXT NOT NULL DEFAULT '*',
    "fixedVersion" TEXT,
    "remediation" TEXT,
    "references" TEXT[],
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "organizationId" TEXT,
    "projectId" TEXT,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ManualAdvisory_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ManualAdvisory_advisoryId_key" ON "ManualAdvisory"("advisoryId");

-- CreateIndex
CREATE INDEX "ManualAdvisory_advisoryId_idx" ON "ManualAdvisory"("advisoryId");

-- CreateIndex
CREATE INDEX "ManualAdvisory_cveId_idx" ON "ManualAdvisory"("cveId");

-- CreateIndex
CREATE INDEX "ManualAdvisory_packageName_idx" ON "ManualAdvisory"("packageName");

-- CreateIndex
CREATE INDEX "ManualAdvisory_severity_idx" ON "ManualAdvisory"("severity");

-- CreateIndex
CREATE INDEX "ManualAdvisory_isActive_idx" ON "ManualAdvisory"("isActive");

-- CreateIndex
CREATE INDEX "ManualAdvisory_organizationId_idx" ON "ManualAdvisory"("organizationId");

-- CreateIndex
CREATE INDEX "ManualAdvisory_projectId_idx" ON "ManualAdvisory"("projectId");

-- AddForeignKey
ALTER TABLE "ManualAdvisory" ADD CONSTRAINT "ManualAdvisory_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ManualAdvisory" ADD CONSTRAINT "ManualAdvisory_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ManualAdvisory" ADD CONSTRAINT "ManualAdvisory_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
