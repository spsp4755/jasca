CREATE TABLE "SemgrepRule" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "yaml" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SemgrepRule_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "SemgrepRule_name_key" ON "SemgrepRule"("name");
CREATE INDEX "SemgrepRule_isActive_idx" ON "SemgrepRule"("isActive");

ALTER TABLE "SemgrepRule" ADD CONSTRAINT "SemgrepRule_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
