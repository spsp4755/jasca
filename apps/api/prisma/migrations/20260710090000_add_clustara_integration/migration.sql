-- CreateEnum
CREATE TYPE "ClustaraDeliveryType" AS ENUM ('TRIVY', 'SBOM');

-- CreateEnum
CREATE TYPE "ClustaraDeliveryStatus" AS ENUM ('PENDING', 'SENDING', 'SUCCESS', 'FAILED');

-- CreateEnum
CREATE TYPE "ScanArtifactType" AS ENUM ('CYCLONEDX_JSON');

-- CreateTable
CREATE TABLE "ClustaraDelivery" (
    "id" TEXT NOT NULL,
    "scanResultId" TEXT NOT NULL,
    "type" "ClustaraDeliveryType" NOT NULL,
    "status" "ClustaraDeliveryStatus" NOT NULL DEFAULT 'PENDING',
    "clusterId" TEXT NOT NULL,
    "scanner" TEXT,
    "generator" TEXT,
    "imageDigest" TEXT NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "maxAttempts" INTEGER NOT NULL DEFAULT 3,
    "httpStatus" INTEGER,
    "responseSummary" TEXT,
    "lastError" TEXT,
    "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "startedAt" TIMESTAMP(3),
    "succeededAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ClustaraDelivery_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanArtifact" (
    "id" TEXT NOT NULL,
    "scanResultId" TEXT NOT NULL,
    "type" "ScanArtifactType" NOT NULL,
    "filePath" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "generator" TEXT NOT NULL,
    "generatorVersion" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanArtifact_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ClustaraDelivery_scanResultId_type_clusterId_imageDigest_key" ON "ClustaraDelivery"("scanResultId", "type", "clusterId", "imageDigest");

-- CreateIndex
CREATE INDEX "ClustaraDelivery_status_nextAttemptAt_idx" ON "ClustaraDelivery"("status", "nextAttemptAt");

-- CreateIndex
CREATE INDEX "ClustaraDelivery_scanResultId_createdAt_idx" ON "ClustaraDelivery"("scanResultId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "ScanArtifact_scanResultId_type_key" ON "ScanArtifact"("scanResultId", "type");

-- CreateIndex
CREATE INDEX "ScanArtifact_scanResultId_createdAt_idx" ON "ScanArtifact"("scanResultId", "createdAt");

-- AddForeignKey
ALTER TABLE "ClustaraDelivery" ADD CONSTRAINT "ClustaraDelivery_scanResultId_fkey" FOREIGN KEY ("scanResultId") REFERENCES "ScanResult"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanArtifact" ADD CONSTRAINT "ScanArtifact_scanResultId_fkey" FOREIGN KEY ("scanResultId") REFERENCES "ScanResult"("id") ON DELETE CASCADE ON UPDATE CASCADE;
