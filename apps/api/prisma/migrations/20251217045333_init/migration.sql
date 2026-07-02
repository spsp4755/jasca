-- CreateEnum
CREATE TYPE "RegistryType" AS ENUM ('DOCKER_HUB', 'HARBOR', 'ECR', 'GCR', 'ACR', 'NEXUS', 'ARTIFACTORY', 'OTHER');

-- CreateEnum
CREATE TYPE "Role" AS ENUM ('SYSTEM_ADMIN', 'ORG_ADMIN', 'PROJECT_ADMIN', 'DEVELOPER', 'VIEWER');

-- CreateEnum
CREATE TYPE "RoleScope" AS ENUM ('SYSTEM', 'ORGANIZATION', 'PROJECT');

-- CreateEnum
CREATE TYPE "SourceType" AS ENUM ('TRIVY_JSON', 'TRIVY_SARIF', 'CI_BAMBOO', 'CI_GITLAB', 'CI_JENKINS', 'CI_GITHUB_ACTIONS', 'MANUAL');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "VulnStatus" AS ENUM ('OPEN', 'ASSIGNED', 'IN_PROGRESS', 'FIX_SUBMITTED', 'VERIFYING', 'FIXED', 'CLOSED', 'IGNORED', 'FALSE_POSITIVE');

-- CreateEnum
CREATE TYPE "Environment" AS ENUM ('ALL', 'DEVELOPMENT', 'STAGING', 'PRODUCTION');

-- CreateEnum
CREATE TYPE "PolicyRuleType" AS ENUM ('SEVERITY_THRESHOLD', 'CVSS_THRESHOLD', 'CVE_BLOCKLIST', 'PACKAGE_BLOCKLIST', 'CVE_AGE', 'CUSTOM');

-- CreateEnum
CREATE TYPE "PolicyAction" AS ENUM ('BLOCK', 'WARN', 'INFO', 'ALLOW');

-- CreateEnum
CREATE TYPE "ExceptionType" AS ENUM ('CVE', 'PACKAGE', 'IMAGE', 'SEVERITY');

-- CreateEnum
CREATE TYPE "ExceptionStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "ChannelType" AS ENUM ('SLACK', 'MATTERMOST', 'EMAIL', 'WEBHOOK');

-- CreateEnum
CREATE TYPE "NotificationEventType" AS ENUM ('NEW_CRITICAL_VULN', 'NEW_HIGH_VULN', 'POLICY_VIOLATION', 'EXCEPTION_REQUESTED', 'EXCEPTION_APPROVED', 'EXCEPTION_EXPIRING', 'SCAN_COMPLETED');

-- CreateEnum
CREATE TYPE "ReportType" AS ENUM ('VULNERABILITY_SUMMARY', 'TREND_ANALYSIS', 'COMPLIANCE_AUDIT', 'PROJECT_STATUS', 'CUSTOM');

-- CreateEnum
CREATE TYPE "ReportStatus" AS ENUM ('PENDING', 'GENERATING', 'COMPLETED', 'FAILED');

-- CreateEnum
CREATE TYPE "CriticalityLevel" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');

-- CreateEnum
CREATE TYPE "ExposureLevel" AS ENUM ('INTERNET', 'DMZ', 'INTERNAL', 'ISOLATED');

-- CreateEnum
CREATE TYPE "EvidenceType" AS ENUM ('PR_LINK', 'COMMIT', 'IMAGE_TAG_CHANGE', 'PACKAGE_UPGRADE', 'PATCH_APPLIED', 'CONFIG_CHANGE', 'WORKAROUND', 'DOCUMENTATION', 'OTHER');

-- CreateEnum
CREATE TYPE "GitProvider" AS ENUM ('GITHUB', 'GITLAB', 'BITBUCKET', 'AZURE_DEVOPS');

-- CreateEnum
CREATE TYPE "IssueTrackerProvider" AS ENUM ('JIRA', 'LINEAR', 'GITHUB_ISSUES', 'GITLAB_ISSUES', 'AZURE_DEVOPS', 'ASANA');

-- CreateTable
CREATE TABLE "Organization" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Project" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "description" TEXT,
    "organizationId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Project_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Registry" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "type" "RegistryType" NOT NULL DEFAULT 'DOCKER_HUB',
    "projectId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Registry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "organizationId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "lastLoginAt" TIMESTAMP(3),

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserRole" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "role" "Role" NOT NULL,
    "scope" "RoleScope" NOT NULL DEFAULT 'ORGANIZATION',
    "scopeId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserRole_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApiToken" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "tokenPrefix" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "permissions" TEXT[],
    "expiresAt" TIMESTAMP(3),
    "lastUsedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ApiToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanResult" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "imageRef" TEXT NOT NULL,
    "imageDigest" TEXT,
    "tag" TEXT,
    "commitHash" TEXT,
    "branch" TEXT,
    "ciPipeline" TEXT,
    "ciJobUrl" TEXT,
    "sourceType" "SourceType" NOT NULL,
    "trivyVersion" TEXT,
    "schemaVersion" TEXT,
    "rawResult" JSONB NOT NULL,
    "artifactName" TEXT,
    "artifactType" TEXT,
    "scannedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanResult_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanSummary" (
    "id" TEXT NOT NULL,
    "scanResultId" TEXT NOT NULL,
    "totalVulns" INTEGER NOT NULL DEFAULT 0,
    "critical" INTEGER NOT NULL DEFAULT 0,
    "high" INTEGER NOT NULL DEFAULT 0,
    "medium" INTEGER NOT NULL DEFAULT 0,
    "low" INTEGER NOT NULL DEFAULT 0,
    "unknown" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "ScanSummary_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Vulnerability" (
    "id" TEXT NOT NULL,
    "cveId" TEXT NOT NULL,
    "title" TEXT,
    "description" TEXT,
    "severity" "Severity" NOT NULL,
    "cvssV2Score" DOUBLE PRECISION,
    "cvssV2Vector" TEXT,
    "cvssV3Score" DOUBLE PRECISION,
    "cvssV3Vector" TEXT,
    "references" TEXT[],
    "cweIds" TEXT[],
    "publishedAt" TIMESTAMP(3),
    "lastModifiedAt" TIMESTAMP(3),
    "isZeroDay" BOOLEAN NOT NULL DEFAULT false,
    "zeroDetectedAt" TIMESTAMP(3),
    "exploitAvailable" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Vulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanVulnerability" (
    "id" TEXT NOT NULL,
    "scanResultId" TEXT NOT NULL,
    "vulnerabilityId" TEXT NOT NULL,
    "pkgName" TEXT NOT NULL,
    "pkgVersion" TEXT NOT NULL,
    "fixedVersion" TEXT,
    "pkgPath" TEXT,
    "layer" JSONB,
    "status" "VulnStatus" NOT NULL DEFAULT 'OPEN',
    "assigneeId" TEXT,
    "vulnHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanVulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VulnerabilityComment" (
    "id" TEXT NOT NULL,
    "scanVulnerabilityId" TEXT NOT NULL,
    "authorId" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "VulnerabilityComment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Policy" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "environment" "Environment" NOT NULL DEFAULT 'ALL',
    "organizationId" TEXT,
    "projectId" TEXT,
    "parentPolicyId" TEXT,
    "isInherited" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Policy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PolicyRule" (
    "id" TEXT NOT NULL,
    "policyId" TEXT NOT NULL,
    "ruleType" "PolicyRuleType" NOT NULL,
    "conditions" JSONB NOT NULL,
    "action" "PolicyAction" NOT NULL,
    "message" TEXT,
    "priority" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PolicyRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PolicyException" (
    "id" TEXT NOT NULL,
    "policyId" TEXT NOT NULL,
    "exceptionType" "ExceptionType" NOT NULL,
    "targetValue" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "status" "ExceptionStatus" NOT NULL DEFAULT 'PENDING',
    "requestedById" TEXT NOT NULL,
    "approvedById" TEXT,
    "expiresAt" TIMESTAMP(3),
    "isExpired" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PolicyException_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NotificationChannel" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" "ChannelType" NOT NULL,
    "config" JSONB NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NotificationChannel_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NotificationRule" (
    "id" TEXT NOT NULL,
    "channelId" TEXT NOT NULL,
    "eventType" "NotificationEventType" NOT NULL,
    "conditions" JSONB,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NotificationRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT,
    "userId" TEXT,
    "action" TEXT NOT NULL,
    "resource" TEXT NOT NULL,
    "resourceId" TEXT,
    "details" JSONB,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ReportTemplate" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "type" "ReportType" NOT NULL,
    "config" JSONB NOT NULL,
    "isSystem" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ReportTemplate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Report" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "templateId" TEXT NOT NULL,
    "parameters" JSONB NOT NULL,
    "status" "ReportStatus" NOT NULL DEFAULT 'PENDING',
    "filePath" TEXT,
    "fileType" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "Report_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MergedVulnerability" (
    "id" TEXT NOT NULL,
    "cveId" TEXT NOT NULL,
    "primaryVulnId" TEXT NOT NULL,
    "mergedVulnIds" TEXT[],
    "mergeReason" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MergedVulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VulnerabilityImpact" (
    "id" TEXT NOT NULL,
    "vulnerabilityId" TEXT NOT NULL,
    "affectedProjects" TEXT[],
    "affectedImages" TEXT[],
    "affectedServices" TEXT[],
    "impactScore" DOUBLE PRECISION NOT NULL,
    "calculatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VulnerabilityImpact_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MitreMapping" (
    "id" TEXT NOT NULL,
    "vulnerabilityId" TEXT NOT NULL,
    "techniqueId" TEXT NOT NULL,
    "techniqueName" TEXT NOT NULL,
    "tacticId" TEXT NOT NULL,
    "tacticName" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.5,

    CONSTRAINT "MitreMapping_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VulnerabilityBookmark" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "vulnerabilityId" TEXT NOT NULL,
    "note" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VulnerabilityBookmark_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskScoreConfig" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "exposureWeight" DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    "assetWeight" DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    "cvssWeight" DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    "exploitWeight" DOUBLE PRECISION NOT NULL DEFAULT 1.5,
    "customFormula" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RiskScoreConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AssetCriticality" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "criticalityLevel" "CriticalityLevel" NOT NULL DEFAULT 'MEDIUM',
    "exposureLevel" "ExposureLevel" NOT NULL DEFAULT 'INTERNAL',
    "tags" TEXT[],
    "notes" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AssetCriticality_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VulnerabilityWorkflow" (
    "id" TEXT NOT NULL,
    "scanVulnerabilityId" TEXT NOT NULL,
    "fromStatus" "VulnStatus" NOT NULL,
    "toStatus" "VulnStatus" NOT NULL,
    "changedById" TEXT NOT NULL,
    "comment" TEXT,
    "evidence" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VulnerabilityWorkflow_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FixEvidence" (
    "id" TEXT NOT NULL,
    "scanVulnerabilityId" TEXT NOT NULL,
    "evidenceType" "EvidenceType" NOT NULL,
    "url" TEXT,
    "description" TEXT,
    "attachments" JSONB,
    "previousValue" TEXT,
    "newValue" TEXT,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FixEvidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GitIntegration" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "provider" "GitProvider" NOT NULL,
    "name" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "baseUrl" TEXT,
    "apiToken" TEXT NOT NULL,
    "defaultBranch" TEXT NOT NULL DEFAULT 'main',
    "autoPrGeneration" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GitIntegration_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GitRepository" (
    "id" TEXT NOT NULL,
    "integrationId" TEXT NOT NULL,
    "projectId" TEXT,
    "repoUrl" TEXT NOT NULL,
    "repoOwner" TEXT NOT NULL,
    "repoName" TEXT NOT NULL,
    "defaultBranch" TEXT NOT NULL DEFAULT 'main',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "GitRepository_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IssueTrackerIntegration" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "provider" "IssueTrackerProvider" NOT NULL,
    "name" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "baseUrl" TEXT NOT NULL,
    "apiToken" TEXT NOT NULL,
    "projectKey" TEXT,
    "autoCreateIssues" BOOLEAN NOT NULL DEFAULT false,
    "issueTemplate" JSONB,
    "severityMapping" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IssueTrackerIntegration_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LinkedIssue" (
    "id" TEXT NOT NULL,
    "integrationId" TEXT NOT NULL,
    "scanVulnerabilityId" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "externalUrl" TEXT NOT NULL,
    "status" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "LinkedIssue_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Organization_slug_key" ON "Organization"("slug");

-- CreateIndex
CREATE INDEX "Organization_slug_idx" ON "Organization"("slug");

-- CreateIndex
CREATE INDEX "Project_organizationId_idx" ON "Project"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "Project_organizationId_slug_key" ON "Project"("organizationId", "slug");

-- CreateIndex
CREATE INDEX "Registry_projectId_idx" ON "Registry"("projectId");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_email_idx" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_organizationId_idx" ON "User"("organizationId");

-- CreateIndex
CREATE INDEX "UserRole_userId_idx" ON "UserRole"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "UserRole_userId_role_scope_scopeId_key" ON "UserRole"("userId", "role", "scope", "scopeId");

-- CreateIndex
CREATE UNIQUE INDEX "ApiToken_tokenHash_key" ON "ApiToken"("tokenHash");

-- CreateIndex
CREATE INDEX "ApiToken_tokenHash_idx" ON "ApiToken"("tokenHash");

-- CreateIndex
CREATE INDEX "ApiToken_organizationId_idx" ON "ApiToken"("organizationId");

-- CreateIndex
CREATE INDEX "ScanResult_projectId_createdAt_idx" ON "ScanResult"("projectId", "createdAt");

-- CreateIndex
CREATE INDEX "ScanResult_imageRef_idx" ON "ScanResult"("imageRef");

-- CreateIndex
CREATE INDEX "ScanResult_imageDigest_idx" ON "ScanResult"("imageDigest");

-- CreateIndex
CREATE UNIQUE INDEX "ScanSummary_scanResultId_key" ON "ScanSummary"("scanResultId");

-- CreateIndex
CREATE UNIQUE INDEX "Vulnerability_cveId_key" ON "Vulnerability"("cveId");

-- CreateIndex
CREATE INDEX "Vulnerability_cveId_idx" ON "Vulnerability"("cveId");

-- CreateIndex
CREATE INDEX "Vulnerability_severity_idx" ON "Vulnerability"("severity");

-- CreateIndex
CREATE INDEX "Vulnerability_isZeroDay_idx" ON "Vulnerability"("isZeroDay");

-- CreateIndex
CREATE INDEX "ScanVulnerability_scanResultId_idx" ON "ScanVulnerability"("scanResultId");

-- CreateIndex
CREATE INDEX "ScanVulnerability_vulnerabilityId_idx" ON "ScanVulnerability"("vulnerabilityId");

-- CreateIndex
CREATE INDEX "ScanVulnerability_status_idx" ON "ScanVulnerability"("status");

-- CreateIndex
CREATE INDEX "ScanVulnerability_assigneeId_idx" ON "ScanVulnerability"("assigneeId");

-- CreateIndex
CREATE UNIQUE INDEX "ScanVulnerability_scanResultId_vulnHash_key" ON "ScanVulnerability"("scanResultId", "vulnHash");

-- CreateIndex
CREATE INDEX "VulnerabilityComment_scanVulnerabilityId_idx" ON "VulnerabilityComment"("scanVulnerabilityId");

-- CreateIndex
CREATE INDEX "Policy_organizationId_idx" ON "Policy"("organizationId");

-- CreateIndex
CREATE INDEX "Policy_projectId_idx" ON "Policy"("projectId");

-- CreateIndex
CREATE INDEX "Policy_environment_idx" ON "Policy"("environment");

-- CreateIndex
CREATE INDEX "PolicyRule_policyId_idx" ON "PolicyRule"("policyId");

-- CreateIndex
CREATE INDEX "PolicyException_policyId_idx" ON "PolicyException"("policyId");

-- CreateIndex
CREATE INDEX "PolicyException_status_idx" ON "PolicyException"("status");

-- CreateIndex
CREATE INDEX "PolicyException_expiresAt_idx" ON "PolicyException"("expiresAt");

-- CreateIndex
CREATE INDEX "NotificationRule_channelId_idx" ON "NotificationRule"("channelId");

-- CreateIndex
CREATE INDEX "AuditLog_organizationId_createdAt_idx" ON "AuditLog"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "AuditLog_userId_idx" ON "AuditLog"("userId");

-- CreateIndex
CREATE INDEX "AuditLog_action_idx" ON "AuditLog"("action");

-- CreateIndex
CREATE INDEX "AuditLog_resource_idx" ON "AuditLog"("resource");

-- CreateIndex
CREATE INDEX "Report_templateId_idx" ON "Report"("templateId");

-- CreateIndex
CREATE INDEX "Report_status_idx" ON "Report"("status");

-- CreateIndex
CREATE INDEX "MergedVulnerability_cveId_idx" ON "MergedVulnerability"("cveId");

-- CreateIndex
CREATE UNIQUE INDEX "VulnerabilityImpact_vulnerabilityId_key" ON "VulnerabilityImpact"("vulnerabilityId");

-- CreateIndex
CREATE INDEX "VulnerabilityImpact_vulnerabilityId_idx" ON "VulnerabilityImpact"("vulnerabilityId");

-- CreateIndex
CREATE INDEX "MitreMapping_vulnerabilityId_idx" ON "MitreMapping"("vulnerabilityId");

-- CreateIndex
CREATE UNIQUE INDEX "MitreMapping_vulnerabilityId_techniqueId_key" ON "MitreMapping"("vulnerabilityId", "techniqueId");

-- CreateIndex
CREATE INDEX "VulnerabilityBookmark_userId_idx" ON "VulnerabilityBookmark"("userId");

-- CreateIndex
CREATE INDEX "VulnerabilityBookmark_vulnerabilityId_idx" ON "VulnerabilityBookmark"("vulnerabilityId");

-- CreateIndex
CREATE UNIQUE INDEX "VulnerabilityBookmark_userId_vulnerabilityId_key" ON "VulnerabilityBookmark"("userId", "vulnerabilityId");

-- CreateIndex
CREATE UNIQUE INDEX "RiskScoreConfig_organizationId_key" ON "RiskScoreConfig"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "AssetCriticality_projectId_key" ON "AssetCriticality"("projectId");

-- CreateIndex
CREATE INDEX "VulnerabilityWorkflow_scanVulnerabilityId_idx" ON "VulnerabilityWorkflow"("scanVulnerabilityId");

-- CreateIndex
CREATE INDEX "VulnerabilityWorkflow_changedById_idx" ON "VulnerabilityWorkflow"("changedById");

-- CreateIndex
CREATE INDEX "VulnerabilityWorkflow_createdAt_idx" ON "VulnerabilityWorkflow"("createdAt");

-- CreateIndex
CREATE INDEX "FixEvidence_scanVulnerabilityId_idx" ON "FixEvidence"("scanVulnerabilityId");

-- CreateIndex
CREATE INDEX "FixEvidence_evidenceType_idx" ON "FixEvidence"("evidenceType");

-- CreateIndex
CREATE INDEX "GitIntegration_organizationId_idx" ON "GitIntegration"("organizationId");

-- CreateIndex
CREATE INDEX "GitRepository_integrationId_idx" ON "GitRepository"("integrationId");

-- CreateIndex
CREATE INDEX "GitRepository_projectId_idx" ON "GitRepository"("projectId");

-- CreateIndex
CREATE INDEX "IssueTrackerIntegration_organizationId_idx" ON "IssueTrackerIntegration"("organizationId");

-- CreateIndex
CREATE INDEX "LinkedIssue_scanVulnerabilityId_idx" ON "LinkedIssue"("scanVulnerabilityId");

-- CreateIndex
CREATE UNIQUE INDEX "LinkedIssue_integrationId_scanVulnerabilityId_key" ON "LinkedIssue"("integrationId", "scanVulnerabilityId");

-- AddForeignKey
ALTER TABLE "Project" ADD CONSTRAINT "Project_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Registry" ADD CONSTRAINT "Registry_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserRole" ADD CONSTRAINT "UserRole_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApiToken" ADD CONSTRAINT "ApiToken_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanResult" ADD CONSTRAINT "ScanResult_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanSummary" ADD CONSTRAINT "ScanSummary_scanResultId_fkey" FOREIGN KEY ("scanResultId") REFERENCES "ScanResult"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanVulnerability" ADD CONSTRAINT "ScanVulnerability_scanResultId_fkey" FOREIGN KEY ("scanResultId") REFERENCES "ScanResult"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanVulnerability" ADD CONSTRAINT "ScanVulnerability_vulnerabilityId_fkey" FOREIGN KEY ("vulnerabilityId") REFERENCES "Vulnerability"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanVulnerability" ADD CONSTRAINT "ScanVulnerability_assigneeId_fkey" FOREIGN KEY ("assigneeId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VulnerabilityComment" ADD CONSTRAINT "VulnerabilityComment_scanVulnerabilityId_fkey" FOREIGN KEY ("scanVulnerabilityId") REFERENCES "ScanVulnerability"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VulnerabilityComment" ADD CONSTRAINT "VulnerabilityComment_authorId_fkey" FOREIGN KEY ("authorId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Policy" ADD CONSTRAINT "Policy_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Policy" ADD CONSTRAINT "Policy_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Policy" ADD CONSTRAINT "Policy_parentPolicyId_fkey" FOREIGN KEY ("parentPolicyId") REFERENCES "Policy"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PolicyRule" ADD CONSTRAINT "PolicyRule_policyId_fkey" FOREIGN KEY ("policyId") REFERENCES "Policy"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PolicyException" ADD CONSTRAINT "PolicyException_policyId_fkey" FOREIGN KEY ("policyId") REFERENCES "Policy"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PolicyException" ADD CONSTRAINT "PolicyException_requestedById_fkey" FOREIGN KEY ("requestedById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PolicyException" ADD CONSTRAINT "PolicyException_approvedById_fkey" FOREIGN KEY ("approvedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NotificationRule" ADD CONSTRAINT "NotificationRule_channelId_fkey" FOREIGN KEY ("channelId") REFERENCES "NotificationChannel"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_templateId_fkey" FOREIGN KEY ("templateId") REFERENCES "ReportTemplate"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VulnerabilityImpact" ADD CONSTRAINT "VulnerabilityImpact_vulnerabilityId_fkey" FOREIGN KEY ("vulnerabilityId") REFERENCES "Vulnerability"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MitreMapping" ADD CONSTRAINT "MitreMapping_vulnerabilityId_fkey" FOREIGN KEY ("vulnerabilityId") REFERENCES "Vulnerability"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VulnerabilityBookmark" ADD CONSTRAINT "VulnerabilityBookmark_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VulnerabilityBookmark" ADD CONSTRAINT "VulnerabilityBookmark_vulnerabilityId_fkey" FOREIGN KEY ("vulnerabilityId") REFERENCES "Vulnerability"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RiskScoreConfig" ADD CONSTRAINT "RiskScoreConfig_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AssetCriticality" ADD CONSTRAINT "AssetCriticality_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VulnerabilityWorkflow" ADD CONSTRAINT "VulnerabilityWorkflow_scanVulnerabilityId_fkey" FOREIGN KEY ("scanVulnerabilityId") REFERENCES "ScanVulnerability"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VulnerabilityWorkflow" ADD CONSTRAINT "VulnerabilityWorkflow_changedById_fkey" FOREIGN KEY ("changedById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FixEvidence" ADD CONSTRAINT "FixEvidence_scanVulnerabilityId_fkey" FOREIGN KEY ("scanVulnerabilityId") REFERENCES "ScanVulnerability"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FixEvidence" ADD CONSTRAINT "FixEvidence_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GitIntegration" ADD CONSTRAINT "GitIntegration_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GitRepository" ADD CONSTRAINT "GitRepository_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "GitIntegration"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GitRepository" ADD CONSTRAINT "GitRepository_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IssueTrackerIntegration" ADD CONSTRAINT "IssueTrackerIntegration_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LinkedIssue" ADD CONSTRAINT "LinkedIssue_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "IssueTrackerIntegration"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LinkedIssue" ADD CONSTRAINT "LinkedIssue_scanVulnerabilityId_fkey" FOREIGN KEY ("scanVulnerabilityId") REFERENCES "ScanVulnerability"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
