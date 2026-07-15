ALTER TYPE "AiExecutionStatus" ADD VALUE 'QUEUED';
ALTER TYPE "AiExecutionStatus" ADD VALUE 'RUNNING';
ALTER TYPE "AiExecutionStatus" ADD VALUE 'CANCELLED';

ALTER TABLE "AiExecution"
    ADD COLUMN "attempts" INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN "startedAt" TIMESTAMP(3),
    ADD COLUMN "completedAt" TIMESTAMP(3),
    ADD COLUMN "notificationClaimedAt" TIMESTAMP(3),
    ADD COLUMN "notificationSentAt" TIMESTAMP(3),
    ADD COLUMN "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE "AiExecution"
    ALTER COLUMN "updatedAt" DROP DEFAULT;

CREATE INDEX "AiExecution_status_createdAt_idx"
    ON "AiExecution"("status", "createdAt");
