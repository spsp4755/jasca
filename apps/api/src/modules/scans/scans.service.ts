import { Injectable, NotFoundException, BadRequestException, Logger } from '@nestjs/common';
import { NotificationEventType, Role, RoleScope } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { TrivyParserService, ParsedScanResult } from './services/trivy-parser.service';
import { CheckovParserService } from './services/checkov-parser.service';
import { ZapParserService } from './services/zap-parser.service';
import { SarifParserService } from './services/sarif-parser.service';
import { VulnSyncService } from './services/vuln-sync.service';
import { LicenseParserService } from '../licenses/services/license-parser.service';
import { UploadScanDto } from './dto/upload-scan.dto';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { PolicyEngineService } from '../policies/policy-engine.service';
import { ManualAdvisoriesService } from '../manual-advisories/manual-advisories.service';
import { NotificationsService } from '../notifications/notifications.service';
import {
    RequestUser,
    assertOrganizationAccess,
    assertProjectAccess,
    getScopedOrganizationIds,
    getUserRoles,
    isSystemAdmin,
} from '../../common/authz/access-control';

@Injectable()
export class ScansService {
    private readonly logger = new Logger(ScansService.name);
    private readonly scanResultDir = process.env.SCAN_RESULT_DIR || '/app/jasca/scan-results';
    private readonly scanResultRetentionDays = Number(process.env.SCAN_RESULT_RETENTION_DAYS || 0);

    constructor(
        private readonly prisma: PrismaService,
        private readonly trivyParser: TrivyParserService,
        private readonly checkovParser: CheckovParserService,
        private readonly zapParser: ZapParserService,
        private readonly sarifParser: SarifParserService,
        private readonly licenseParser: LicenseParserService,
        private readonly vulnSyncService: VulnSyncService,
        private readonly policyEngine: PolicyEngineService,
        private readonly manualAdvisoriesService: ManualAdvisoriesService,
        private readonly notificationsService: NotificationsService,
    ) { }

    private getDisplayTargetName(scan: { imageRef?: string | null; artifactName?: string | null }) {
        return scan.imageRef || this.basename(scan.artifactName) || scan.artifactName || 'Unknown';
    }

    private getScanEvidence(rawResult: any) {
        const evidence = rawResult?.Metadata?.JascaScanEvidence;
        if (evidence) return evidence;

        // Uploaded SARIF files carry no JascaScanEvidence; derive the scanner
        // from the SARIF tool driver so the UI can attribute the result.
        const driver = rawResult?.runs?.[0]?.tool?.driver;
        if (driver?.name) {
            return {
                scanner: String(driver.name).toLowerCase(),
                sourceType: 'SARIF',
                toolVersion: driver.version,
            };
        }

        return null;
    }

    private getTotalFindingCount(summary?: { critical?: number; high?: number; medium?: number; low?: number; unknown?: number; total?: number }) {
        if (!summary) return 0;
        return summary.total ?? (
            (summary.critical || 0) +
            (summary.high || 0) +
            (summary.medium || 0) +
            (summary.low || 0) +
            (summary.unknown || 0)
        );
    }

    private async getScanNotificationRecipients(projectId: string, uploadedById?: string) {
        const project = await this.prisma.project.findUnique({
            where: { id: projectId },
            select: { organizationId: true },
        });

        const users = await this.prisma.user.findMany({
            where: {
                isActive: true,
                OR: [
                    uploadedById ? { id: uploadedById } : undefined,
                    {
                        roles: {
                            some: {
                                OR: [
                                    { role: Role.SYSTEM_ADMIN, scope: { in: [RoleScope.GLOBAL, RoleScope.SYSTEM] } },
                                    { role: Role.SECURITY_ADMIN, scope: { in: [RoleScope.GLOBAL, RoleScope.SYSTEM] } },
                                    project?.organizationId
                                        ? { role: { in: [Role.ORG_ADMIN, Role.SECURITY_ADMIN] }, scope: RoleScope.ORGANIZATION, scopeId: project.organizationId }
                                        : undefined,
                                    { role: { in: [Role.PROJECT_ADMIN, Role.SECURITY_ADMIN] }, scope: RoleScope.PROJECT, scopeId: projectId },
                                ].filter(Boolean) as any[],
                            },
                        },
                    },
                ].filter(Boolean) as any[],
            },
            select: {
                id: true,
                notificationSettings: {
                    select: {
                        emailAlerts: true,
                        criticalOnly: true,
                        scanComplete: true,
                        criticalVulns: true,
                        highVulns: true,
                        policyViolations: true,
                        exceptionAlerts: true,
                    },
                },
            },
        });

        return users;
    }

    private async sendExternalNotification(payload: Parameters<NotificationsService['notify']>[0]) {
        try {
            await this.notificationsService.notify(payload);
        } catch (error) {
            this.logger.warn(`Failed to send external notification: ${(error as Error).message}`);
        }
    }

    private filterNotificationRecipients(
        recipients: Array<{
            id: string;
            notificationSettings?: {
                emailAlerts: boolean;
                criticalOnly: boolean;
                criticalVulns?: boolean;
                highVulns?: boolean;
                policyViolations?: boolean;
                exceptionAlerts?: boolean;
            } | null;
        }>,
        severity?: string,
        category: 'vulnerability' | 'policy' | 'exception' = 'vulnerability',
    ) {
        const normalizedSeverity = severity?.toUpperCase();
        const isCritical = normalizedSeverity === 'CRITICAL';
        const isHigh = normalizedSeverity === 'HIGH';

        return recipients
            .filter((user) => user.notificationSettings?.emailAlerts !== false)
            .filter((user) => !user.notificationSettings?.criticalOnly || isCritical)
            .filter((user) => {
                const settings = user.notificationSettings;
                if (category === 'policy') return settings?.policyViolations !== false;
                if (category === 'exception') return settings?.exceptionAlerts !== false;
                if (isCritical) return settings?.criticalVulns !== false;
                if (isHigh) return settings?.highVulns !== false;
                return true;
            })
            .map((user) => user.id);
    }

    private filterScanCompleteRecipients(
        recipients: Array<{
            id: string;
            notificationSettings?: { emailAlerts: boolean; scanComplete?: boolean } | null;
        }>,
    ) {
        return recipients
            .filter((user) => user.notificationSettings?.emailAlerts !== false)
            .filter((user) => user.notificationSettings?.scanComplete !== false)
            .map((user) => user.id);
    }

    private async emitScanNotifications(
        projectId: string,
        scan: any,
        policyEvaluation: any,
        uploadedById?: string,
    ) {
        const recipients = await this.getScanNotificationRecipients(projectId, uploadedById);
        const targetName = scan.targetName || scan.imageRef || scan.artifactName || 'Unknown target';
        const summary = scan.summary || {};
        const critical = summary.critical || 0;
        const high = summary.high || 0;
        const total = this.getTotalFindingCount(summary);
        const link = `/dashboard/scans/${scan.id}`;
        const scanTitle = `스캔 완료: ${targetName}`;
        const scanMessage = `취약점 ${total}건이 발견되었습니다. Critical ${critical}건, High ${high}건입니다.`;
        const scanRecipients = this.filterScanCompleteRecipients(recipients);

        await this.notificationsService.createNotificationsForUsers(
            scanRecipients,
            'scan_complete',
            scanTitle,
            scanMessage,
            link,
        );
        await this.sendExternalNotification({
            eventType: NotificationEventType.SCAN_COMPLETED,
            title: scanTitle,
            message: scanMessage,
            severity: total > 0 ? 'INFO' : 'LOW',
            projectId,
            link,
        });

        if (critical > 0 || high > 0) {
            const severity = critical > 0 ? 'CRITICAL' : 'HIGH';
            const type = critical > 0 ? 'critical_vuln' : 'high_vuln';
            const title = `${severity} 취약점 발견: ${targetName}`;
            const message = `Critical ${critical}건, High ${high}건이 발견되었습니다. 상세 화면에서 조치 대상을 확인하세요.`;
            const alertRecipients = this.filterNotificationRecipients(recipients, severity);

            await this.notificationsService.createNotificationsForUsers(alertRecipients, type, title, message, link);
            await this.sendExternalNotification({
                eventType: critical > 0 ? NotificationEventType.NEW_CRITICAL_VULN : NotificationEventType.NEW_HIGH_VULN,
                title,
                message,
                severity,
                projectId,
                link,
            });
        }

        const policyAlerts = [
            ...(policyEvaluation?.violations || []),
            ...(policyEvaluation?.warnings || []),
        ].filter((violation) => violation.sendNotification);

        for (const violation of policyAlerts) {
            const title = `정책 위반: ${violation.policyName}`;
            const message = `${violation.ruleName} 규칙에 ${violation.count}건이 매칭되었습니다.`;
            await this.notificationsService.createNotificationsForUsers(
                this.filterNotificationRecipients(recipients, violation.severity, 'policy'),
                'policy_violation',
                title,
                message,
                link,
            );
            try {
                await this.notificationsService.notifyPolicyViolation({
                    policyName: violation.policyName,
                    ruleName: violation.ruleName,
                    action: violation.action,
                    severity: violation.severity,
                    projectName: scan.project?.name,
                    cveId: violation.cveIds?.[0],
                    details: message,
                });
            } catch (error) {
                this.logger.warn(`Failed to send policy violation notification: ${(error as Error).message}`);
            }
        }
    }

    private basename(value?: string | null) {
        if (!value) return undefined;
        const normalized = value.replace(/\\/g, '/').replace(/\/+$/, '');
        return normalized.split('/').filter(Boolean).pop();
    }

    private buildScanAccessWhere(currentUser?: RequestUser, projectId?: string) {
        if (projectId) {
            return { projectId };
        }

        if (!currentUser || isSystemAdmin(currentUser)) {
            return undefined;
        }

        const organizationIds = getScopedOrganizationIds(currentUser) || [];
        const projectIds = getUserRoles(currentUser)
            .filter((role) => role.scope === 'PROJECT' && role.scopeId)
            .map((role) => role.scopeId as string);
        const filters: any[] = [];

        if (organizationIds.length > 0) {
            filters.push({ project: { organizationId: { in: organizationIds } } });
        }
        if (projectIds.length > 0) {
            filters.push({ projectId: { in: projectIds } });
        }

        return filters.length > 0 ? { OR: filters } : { id: '__no_access__' };
    }

    async findAll(projectId?: string, options?: { limit?: number; offset?: number }, currentUser?: RequestUser) {
        if (projectId && currentUser) {
            const project = await this.prisma.project.findUnique({ where: { id: projectId } });
            if (!project) throw new NotFoundException('Project not found');
            assertProjectAccess(currentUser, project);
        }

        const where = this.buildScanAccessWhere(currentUser, projectId);

        const [results, total] = await Promise.all([
            this.prisma.scanResult.findMany({
                where,
                include: {
                    project: { include: { organization: true } },
                    summary: true,
                },
                orderBy: { createdAt: 'desc' },
                take: options?.limit || 20,
                skip: options?.offset || 0,
            }),
            this.prisma.scanResult.count({ where }),
        ]);

        // Transform to match frontend Scan interface
        const transformedResults = results.map(scan => ({
            id: scan.id,
            projectId: scan.projectId,
            targetName: this.getDisplayTargetName(scan),
            scanLocation: scan.artifactName,
            scanType: scan.sourceType || 'UNKNOWN',
            sourceType: scan.sourceType,
            status: scan.summary ? 'COMPLETED' : 'PENDING',
            startedAt: scan.scannedAt?.toISOString() || scan.createdAt.toISOString(),
            completedAt: scan.summary ? scan.createdAt.toISOString() : undefined,
            createdAt: scan.createdAt.toISOString(),
            imageRef: scan.imageRef,
            imageDigest: scan.imageDigest,
            tag: scan.tag,
            artifactName: scan.artifactName,
            artifactType: scan.artifactType,
            summary: scan.summary ? {
                critical: scan.summary.critical,
                high: scan.summary.high,
                medium: scan.summary.medium,
                low: scan.summary.low,
                unknown: scan.summary.unknown,
                total: scan.summary.totalVulns,
            } : undefined,
            project: scan.project ? {
                id: scan.project.id,
                name: scan.project.name,
                organization: scan.project.organization ? {
                    id: scan.project.organization.id,
                    name: scan.project.organization.name,
                } : undefined,
            } : undefined,
        }));

        return { results: transformedResults, total };
    }

    /**
     * Best-fix suggestions (Checkmarx "Best Fix Location" approximation):
     * groups open findings by their common root so one action resolves many.
     * - package groups: upgrade pkgName to the fixed version -> resolves N CVEs
     * - code groups: same rule in the same file -> fixing the pattern resolves N findings
     */
    async getBestFixes(id: string, currentUser?: RequestUser) {
        const scan = await this.prisma.scanResult.findUnique({
            where: { id },
            include: {
                project: { include: { organization: true } },
                vulnerabilities: {
                    where: { status: { notIn: ['FIXED', 'FALSE_POSITIVE', 'CLOSED'] } },
                    include: { vulnerability: { select: { cveId: true, severity: true, title: true } } },
                },
            },
        });

        if (!scan) {
            throw new NotFoundException('Scan result not found');
        }
        if (currentUser) {
            assertProjectAccess(currentUser, scan.project);
        }

        const severityRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
        const summarize = (items: typeof scan.vulnerabilities) => {
            const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
            let top: string = 'UNKNOWN';
            for (const v of items) {
                const sev = v.vulnerability.severity;
                if (sev === 'CRITICAL') counts.critical += 1;
                else if (sev === 'HIGH') counts.high += 1;
                else if (sev === 'MEDIUM') counts.medium += 1;
                else if (sev === 'LOW') counts.low += 1;
                else counts.unknown += 1;
                if ((severityRank[sev] ?? 0) > (severityRank[top] ?? 0)) top = sev;
            }
            return { ...counts, topSeverity: top };
        };

        const withFix = scan.vulnerabilities.filter((v) => v.fixedVersion);
        const packageGroups = new Map<string, typeof scan.vulnerabilities>();
        for (const v of withFix) {
            const key = v.pkgName;
            packageGroups.set(key, [...(packageGroups.get(key) || []), v]);
        }
        const packageFixes = [...packageGroups.entries()].map(([pkgName, items]) => {
            // ponytail: naive numeric-aware string sort instead of full semver parsing
            const fixedVersions = [...new Set(items.map((v) => v.fixedVersion!))]
                .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
            return {
                type: 'package' as const,
                pkgName,
                currentVersion: items[0].pkgVersion,
                recommendedVersion: fixedVersions[fixedVersions.length - 1],
                resolves: items.length,
                ...summarize(items),
                cveIds: items.map((v) => v.vulnerability.cveId).slice(0, 10),
            };
        });

        const withoutFix = scan.vulnerabilities.filter((v) => !v.fixedVersion);
        const codeGroups = new Map<string, typeof scan.vulnerabilities>();
        for (const v of withoutFix) {
            const key = `${v.vulnerability.cveId}::${v.pkgName}`;
            codeGroups.set(key, [...(codeGroups.get(key) || []), v]);
        }
        const codeFixes = [...codeGroups.entries()]
            .filter(([, items]) => items.length >= 2)
            .map(([key, items]) => ({
                type: 'code' as const,
                ruleId: key.split('::')[0],
                file: key.split('::')[1],
                title: items[0].vulnerability.title,
                locations: items.map((v) => v.pkgVersion).slice(0, 10),
                resolves: items.length,
                ...summarize(items),
            }));

        const byImpact = (a: { resolves: number; topSeverity: string }, b: { resolves: number; topSeverity: string }) =>
            b.resolves - a.resolves || (severityRank[b.topSeverity] ?? 0) - (severityRank[a.topSeverity] ?? 0);

        return {
            scanResultId: scan.id,
            totalOpenFindings: scan.vulnerabilities.length,
            packageFixes: packageFixes.sort(byImpact).slice(0, 20),
            codeFixes: codeFixes.sort(byImpact).slice(0, 20),
        };
    }

    async findById(id: string, currentUser?: RequestUser) {
        const scan = await this.prisma.scanResult.findUnique({
            where: { id },
            include: {
                project: { include: { organization: true } },
                summary: true,
                vulnerabilities: {
                    include: {
                        vulnerability: true,
                        assignee: true,
                    },
                    orderBy: [
                        { vulnerability: { severity: 'asc' } },
                        { createdAt: 'desc' },
                    ],
                },
            },
        });

        if (!scan) {
            throw new NotFoundException('Scan result not found');
        }

        if (currentUser) {
            assertProjectAccess(currentUser, scan.project);
        }

        // Transform to match frontend interface
        return {
            id: scan.id,
            projectId: scan.projectId,
            targetName: this.getDisplayTargetName(scan),
            scanLocation: scan.artifactName,
            scanType: scan.sourceType || 'UNKNOWN',
            sourceType: scan.sourceType,
            status: scan.summary ? 'COMPLETED' : 'PENDING',
            startedAt: scan.scannedAt?.toISOString() || scan.createdAt.toISOString(),
            completedAt: scan.summary ? scan.createdAt.toISOString() : undefined,
            createdAt: scan.createdAt.toISOString(),
            imageRef: scan.imageRef,
            imageDigest: scan.imageDigest,
            tag: scan.tag,
            artifactName: scan.artifactName,
            artifactType: scan.artifactType,
            summary: scan.summary ? {
                critical: scan.summary.critical,
                high: scan.summary.high,
                medium: scan.summary.medium,
                low: scan.summary.low,
                unknown: scan.summary.unknown,
                total: scan.summary.totalVulns,
            } : undefined,
            project: scan.project ? {
                id: scan.project.id,
                name: scan.project.name,
                organization: scan.project.organization ? {
                    id: scan.project.organization.id,
                    name: scan.project.organization.name,
                } : undefined,
            } : undefined,
            vulnerabilities: scan.vulnerabilities.map(v => ({
                id: v.id,
                scanResultId: v.scanResultId,
                vulnerabilityId: v.vulnerabilityId,
                pkgName: v.pkgName,
                installedVersion: v.pkgVersion,
                fixedVersion: v.fixedVersion,
                status: v.status,
                assigneeId: v.assigneeId,
                createdAt: v.createdAt?.toISOString(),
                vulnerability: v.vulnerability ? {
                    id: v.vulnerability.id,
                    cveId: v.vulnerability.cveId,
                    severity: v.vulnerability.severity,
                    title: v.vulnerability.title,
                    description: v.vulnerability.description,
                    cvssScore: v.vulnerability.cvssV3Score,
                    cvssVector: v.vulnerability.cvssV3Vector,
                    publishedDate: v.vulnerability.publishedAt?.toISOString(),
                    references: v.vulnerability.references,
                } : undefined,
                assignee: v.assignee ? {
                    id: v.assignee.id,
                    name: v.assignee.name,
                    email: v.assignee.email,
                } : undefined,
            })),
            scanEvidence: this.getScanEvidence(scan.rawResult),
            rawResult: scan.rawResult,
        };
    }

    async uploadScan(
        projectId: string | undefined,
        dto: UploadScanDto,
        rawResult: any,
        sourceInfo?: { uploaderIp?: string; userAgent?: string; uploadedById?: string },
        currentUser?: RequestUser,
    ) {
        // Parse the scan result first to get artifact info.
        const parsed = dto.sourceType === 'CHECKOV_JSON'
            ? this.checkovParser.parse(rawResult)
            : dto.sourceType === 'ZAP_JSON'
                ? this.zapParser.parse(rawResult)
                : dto.sourceType === 'SARIF'
                    ? this.sarifParser.parse(rawResult)
                    : this.trivyParser.parse(rawResult, dto.sourceType);

        // Resolve project - either use provided projectId or auto-create
        const resolvedProjectId = await this.resolveProject(projectId, dto, parsed.artifactName, currentUser);

        // Create the scan result
        const scanResult = await this.prisma.scanResult.create({
            data: {
                projectId: resolvedProjectId,
                imageRef: dto.imageRef || parsed.artifactName || 'unknown',
                imageDigest: dto.imageDigest,
                tag: dto.tag,
                commitHash: dto.commitHash,
                branch: dto.branch,
                ciPipeline: dto.ciPipeline,
                ciJobUrl: dto.ciJobUrl,
                sourceType: dto.sourceType,
                trivyVersion: parsed.trivyVersion,
                schemaVersion: parsed.schemaVersion,
                rawResult: rawResult,
                artifactName: parsed.artifactName,
                artifactType: parsed.artifactType,
                // Source tracking
                uploaderIp: sourceInfo?.uploaderIp,
                userAgent: sourceInfo?.userAgent,
                uploadedById: sourceInfo?.uploadedById,
            },
        });

        const manualVulnerabilities = await this.manualAdvisoriesService.getManualVulnerabilitiesForScan(
            resolvedProjectId,
            rawResult,
        );
        const allVulnerabilities = this.mergeParsedVulnerabilities(parsed.vulnerabilities, manualVulnerabilities);

        if (manualVulnerabilities.length > 0) {
            this.logger.log(`Matched ${manualVulnerabilities.length} manual advisories for scan ${scanResult.id}`);
        }

        // Process vulnerabilities and collect hashes for sync
        const newVulnHashes = await this.processVulnerabilities(scanResult.id, allVulnerabilities);

        // Sync resolved vulnerabilities (auto-mark FIXED if not in new scan)
        try {
            const syncResult = await this.vulnSyncService.syncResolvedVulnerabilities(
                resolvedProjectId,
                scanResult.id,
                newVulnHashes,
            );
            if (syncResult.resolvedCount > 0) {
                this.logger.log(`Auto-resolved ${syncResult.resolvedCount} vulnerabilities for project ${resolvedProjectId}`);
            }
        } catch (error) {
            this.logger.warn(`Failed to sync resolved vulnerabilities: ${error.message}`);
            // Don't fail the scan upload if sync fails
        }

        // Process licenses from package-oriented scanners only.
        if (dto.sourceType !== 'CHECKOV_JSON' && dto.sourceType !== 'ZAP_JSON' && dto.sourceType !== 'SARIF') {
            try {
                const licenseResult = await this.licenseParser.processLicenses(scanResult.id, rawResult);
                this.logger.log(`Processed ${licenseResult.processed} package licenses for scan ${scanResult.id}`);
            } catch (error) {
                this.logger.warn(`Failed to process licenses for scan ${scanResult.id}: ${error.message}`);
                // Don't fail the scan upload if license processing fails
            }
        }

        // Create summary
        await this.createSummary(scanResult.id);

        // Persist the raw Trivy JSON to a durable location so it can be
        // re-downloaded or reused for AI analysis after the temp upload dir is
        // cleaned up. Best-effort: never fail the scan if persistence fails.
        try {
            const filePath = await this.persistRawResult(scanResult.id, rawResult);
            if (filePath) {
                await this.prisma.scanResult.update({
                    where: { id: scanResult.id },
                    data: { resultFilePath: filePath },
                });
            }
        } catch (error) {
            this.logger.warn(`Failed to persist raw scan result for ${scanResult.id}: ${(error as Error).message}`);
        }

        // Opportunistically prune expired result files.
        this.cleanupExpiredResultFiles().catch(() => undefined);

        let policyEvaluation;
        try {
            policyEvaluation = await this.policyEngine.evaluate(resolvedProjectId, scanResult.id, undefined, currentUser);
        } catch (error) {
            this.logger.warn(`Failed to evaluate policies for scan ${scanResult.id}: ${error.message}`);
        }

        const savedScan = await this.findById(scanResult.id, currentUser);
        try {
            await this.emitScanNotifications(resolvedProjectId, savedScan, policyEvaluation, sourceInfo?.uploadedById);
        } catch (error) {
            this.logger.warn(`Failed to emit scan notifications for ${scanResult.id}: ${(error as Error).message}`);
        }

        return {
            ...savedScan,
            policyEvaluation,
        };
    }

    /**
     * Resolve project ID - either use provided ID, find by name, or auto-create
     */
    private async resolveProject(
        projectId: string | undefined,
        dto: UploadScanDto,
        artifactName?: string,
        currentUser?: RequestUser,
    ): Promise<string> {
        // Case 1: projectId is provided - use it directly
        if (projectId) {
            const project = await this.prisma.project.findUnique({
                where: { id: projectId },
            });
            if (!project) {
                throw new BadRequestException(`Project with ID ${projectId} not found`);
            }
            if (currentUser) {
                assertProjectAccess(currentUser, project);
            }
            return projectId;
        }

        const fallbackOrganizationId = dto.organizationId || currentUser?.organizationId || undefined;

        // Case 2: projectName is provided - find or create
        if (dto.projectName) {
            if (!fallbackOrganizationId) {
                throw new BadRequestException(
                    'organizationId is required when using projectName',
                );
            }

            if (fallbackOrganizationId && currentUser) {
                assertOrganizationAccess(currentUser, fallbackOrganizationId);
            }

            // Try to find existing project by name
            const existingProject = await this.prisma.project.findFirst({
                where: {
                    name: dto.projectName,
                    ...(fallbackOrganizationId ? { organizationId: fallbackOrganizationId } : {}),
                },
            });

            if (existingProject) {
                return existingProject.id;
            }

            const slug = dto.projectName
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/^-|-$/g, '');

            const newProject = await this.prisma.project.create({
                data: {
                    name: dto.projectName,
                    slug: slug || `project-${Date.now()}`,
                    organizationId: fallbackOrganizationId,
                },
            });

            return newProject.id;
        }

        // Case 3: Use artifactName from scan result to create project
        if (artifactName && fallbackOrganizationId) {
            if (currentUser) {
                assertOrganizationAccess(currentUser, fallbackOrganizationId);
            }

            // Extract a project name from artifact (e.g., 'registry.com/my-app:v1' -> 'my-app')
            const projectName = this.extractProjectNameFromArtifact(artifactName);

            // Try to find existing project
            const existingProject = await this.prisma.project.findFirst({
                where: {
                    name: projectName,
                    organizationId: fallbackOrganizationId,
                },
            });

            if (existingProject) {
                return existingProject.id;
            }

            // Create new project
            const slug = projectName
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/^-|-$/g, '');

            const newProject = await this.prisma.project.create({
                data: {
                    name: projectName,
                    slug: slug || `project-${Date.now()}`,
                    organizationId: fallbackOrganizationId,
                },
            });

            return newProject.id;
        }

        throw new BadRequestException(
            'Either projectId, projectName with organizationId, or organizationId (for auto-create from artifact) is required',
        );
    }

    /**
     * Extract a project name from artifact reference (e.g., 'registry.com/org/my-app:v1' -> 'my-app')
     */
    private extractProjectNameFromArtifact(artifactName: string): string {
        // Remove tag/digest
        const withoutTag = artifactName.split(':')[0].split('@')[0];
        // Get the last part after /
        const parts = withoutTag.split('/');
        return parts[parts.length - 1] || 'unknown-project';
    }


    private async processVulnerabilities(
        scanResultId: string,
        vulnerabilities: ParsedScanResult['vulnerabilities'],
    ): Promise<Set<string>> {
        const vulnHashes = new Set<string>();

        for (const vuln of vulnerabilities) {
            // Upsert vulnerability (CVE)
            await this.prisma.vulnerability.upsert({
                where: { cveId: vuln.cveId },
                create: {
                    cveId: vuln.cveId,
                    title: vuln.title,
                    description: vuln.description,
                    severity: vuln.severity,
                    cvssV3Score: vuln.cvssScore,
                    cvssV3Vector: vuln.cvssVector,
                    references: vuln.references,
                    cweIds: vuln.cweIds,
                    publishedAt: vuln.publishedAt,
                    lastModifiedAt: vuln.lastModifiedAt,
                },
                update: {
                    title: vuln.title,
                    description: vuln.description,
                    severity: vuln.severity,
                    cvssV3Score: vuln.cvssScore,
                    cvssV3Vector: vuln.cvssVector,
                    references: vuln.references,
                    cweIds: vuln.cweIds,
                    lastModifiedAt: vuln.lastModifiedAt,
                },
            });

            // Get the vulnerability ID
            const vulnerability = await this.prisma.vulnerability.findUnique({
                where: { cveId: vuln.cveId },
            });

            if (!vulnerability) continue;

            // Create vulnerability hash for deduplication
            const vulnHash = this.generateVulnHash(vuln.cveId, vuln.pkgName, vuln.pkgVersion);
            vulnHashes.add(vulnHash);

            // Create scan-vulnerability mapping
            await this.prisma.scanVulnerability.upsert({
                where: {
                    scanResultId_vulnHash: {
                        scanResultId,
                        vulnHash,
                    },
                },
                create: {
                    scanResultId,
                    vulnerabilityId: vulnerability.id,
                    pkgName: vuln.pkgName,
                    pkgVersion: vuln.pkgVersion,
                    fixedVersion: vuln.fixedVersion,
                    pkgPath: vuln.pkgPath,
                    layer: vuln.layer,
                    vulnHash,
                },
                update: {
                    fixedVersion: vuln.fixedVersion,
                    pkgPath: vuln.pkgPath,
                    layer: vuln.layer,
                },
            });
        }

        return vulnHashes;
    }

    private mergeParsedVulnerabilities(
        trivyVulnerabilities: ParsedScanResult['vulnerabilities'],
        manualVulnerabilities: ParsedScanResult['vulnerabilities'],
    ): ParsedScanResult['vulnerabilities'] {
        const merged = [...trivyVulnerabilities];
        const seen = new Set(
            trivyVulnerabilities.map((vuln) => this.generateVulnHash(vuln.cveId, vuln.pkgName, vuln.pkgVersion)),
        );

        for (const vuln of manualVulnerabilities) {
            const hash = this.generateVulnHash(vuln.cveId, vuln.pkgName, vuln.pkgVersion);
            if (seen.has(hash)) continue;
            seen.add(hash);
            merged.push(vuln);
        }

        return merged;
    }


    private generateVulnHash(cveId: string, pkgName: string, pkgVersion: string): string {
        const data = `${cveId}:${pkgName}:${pkgVersion}`;
        return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
    }

    private async createSummary(scanResultId: string) {
        const counts = await this.prisma.scanVulnerability.groupBy({
            by: ['scanResultId'],
            where: { scanResultId },
            _count: true,
        });

        const severityCounts = await this.prisma.$queryRaw<
            Array<{ severity: string; count: bigint }>
        >`
      SELECT v.severity, COUNT(*) as count
      FROM "ScanVulnerability" sv
      JOIN "Vulnerability" v ON sv."vulnerabilityId" = v.id
      WHERE sv."scanResultId" = ${scanResultId}
      GROUP BY v.severity
    `;

        const summary = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            unknown: 0,
            totalVulns: 0,
        };

        for (const row of severityCounts) {
            const count = Number(row.count);
            summary.totalVulns += count;

            switch (row.severity) {
                case 'CRITICAL':
                    summary.critical = count;
                    break;
                case 'HIGH':
                    summary.high = count;
                    break;
                case 'MEDIUM':
                    summary.medium = count;
                    break;
                case 'LOW':
                    summary.low = count;
                    break;
                default:
                    summary.unknown = count;
            }
        }

        await this.prisma.scanSummary.create({
            data: {
                scanResultId,
                ...summary,
            },
        });
    }

    async delete(id: string, currentUser?: RequestUser) {
        await this.findById(id, currentUser);
        const scan = await this.prisma.scanResult.findUnique({ where: { id }, select: { resultFilePath: true } });
        if (scan?.resultFilePath) {
            await fs.promises.rm(scan.resultFilePath, { force: true }).catch(() => undefined);
        }
        return this.prisma.scanResult.delete({ where: { id } });
    }

    // ===== Raw result persistence (feature 5) =====

    private async persistRawResult(scanId: string, rawResult: any): Promise<string | null> {
        await fs.promises.mkdir(this.scanResultDir, { recursive: true });
        const filePath = path.join(this.scanResultDir, `${scanId}.json`);
        await fs.promises.writeFile(filePath, JSON.stringify(rawResult), 'utf-8');
        return filePath;
    }

    private async cleanupExpiredResultFiles(): Promise<void> {
        if (!this.scanResultRetentionDays || this.scanResultRetentionDays <= 0) return;
        const cutoff = Date.now() - this.scanResultRetentionDays * 24 * 60 * 60 * 1000;
        let entries: string[] = [];
        try {
            entries = await fs.promises.readdir(this.scanResultDir);
        } catch {
            return;
        }
        for (const entry of entries) {
            if (!entry.endsWith('.json')) continue;
            const fullPath = path.join(this.scanResultDir, entry);
            try {
                const stat = await fs.promises.stat(fullPath);
                if (stat.mtimeMs < cutoff) {
                    await fs.promises.rm(fullPath, { force: true });
                    this.logger.log(`Pruned expired scan result file: ${entry}`);
                }
            } catch {
                // ignore individual file errors
            }
        }
    }

    /** Returns the raw Trivy JSON for a scan as a string, from disk if available, else from DB. */
    async getRawResult(id: string, currentUser?: RequestUser): Promise<{ json: string; fileName: string }> {
        const scan = await this.prisma.scanResult.findUnique({
            where: { id },
            include: { project: true },
        });
        if (!scan) throw new NotFoundException('Scan result not found');
        if (currentUser) assertProjectAccess(currentUser, scan.project);

        const fileName = `${id}.json`;
        if (scan.resultFilePath) {
            try {
                const json = await fs.promises.readFile(scan.resultFilePath, 'utf-8');
                return { json, fileName };
            } catch {
                this.logger.warn(`resultFilePath missing on disk for scan ${id}, falling back to DB rawResult`);
            }
        }
        return { json: JSON.stringify(scan.rawResult, null, 2), fileName };
    }

    // ===== Exports (features 2 & 4) =====

    private async loadScanVulnerabilitiesForExport(id: string, currentUser?: RequestUser) {
        const scan = await this.prisma.scanResult.findUnique({
            where: { id },
            include: {
                project: true,
                vulnerabilities: { include: { vulnerability: true } },
            },
        });
        if (!scan) throw new NotFoundException('Scan result not found');
        if (currentUser) assertProjectAccess(currentUser, scan.project);
        return scan;
    }

    async exportVulnerabilities(id: string, format: 'csv' | 'json', currentUser?: RequestUser) {
        const scan = await this.loadScanVulnerabilitiesForExport(id, currentUser);
        const rows = scan.vulnerabilities.map((v) => ({
            cveId: v.vulnerability?.cveId || '',
            severity: v.vulnerability?.severity || '',
            pkgName: v.pkgName,
            installedVersion: v.pkgVersion,
            fixedVersion: v.fixedVersion || '',
            cvssScore: v.vulnerability?.cvssV3Score ?? '',
            title: v.vulnerability?.title || '',
            description: (v.vulnerability?.description || '').replace(/\r?\n/g, ' '),
            status: v.status,
        }));

        if (format === 'json') {
            return { content: JSON.stringify(rows, null, 2), fileName: `scan-${id}-vulnerabilities.json`, contentType: 'application/json' };
        }
        const headers = ['cveId', 'severity', 'pkgName', 'installedVersion', 'fixedVersion', 'cvssScore', 'title', 'description', 'status'];
        return { content: this.toCsv(headers, rows), fileName: `scan-${id}-vulnerabilities.csv`, contentType: 'text/csv' };
    }

    async exportLicenses(id: string, format: 'csv' | 'json', currentUser?: RequestUser) {
        const scan = await this.prisma.scanResult.findUnique({
            where: { id },
            include: { project: true, packageLicenses: { include: { license: true } } },
        });
        if (!scan) throw new NotFoundException('Scan result not found');
        if (currentUser) assertProjectAccess(currentUser, scan.project);

        const rows = scan.packageLicenses.map((l) => ({
            pkgName: l.pkgName,
            pkgVersion: l.pkgVersion,
            licenseName: l.licenseName,
            spdxId: l.license?.spdxId || '',
            classification: l.license?.classification || '',
            pkgPath: l.pkgPath || '',
        }));

        if (format === 'json') {
            return { content: JSON.stringify(rows, null, 2), fileName: `scan-${id}-licenses.json`, contentType: 'application/json' };
        }
        const headers = ['pkgName', 'pkgVersion', 'licenseName', 'spdxId', 'classification', 'pkgPath'];
        return { content: this.toCsv(headers, rows), fileName: `scan-${id}-licenses.csv`, contentType: 'text/csv' };
    }

    /**
     * Export multiple scans as a single combined file.
     *
     *  - JSON: a structured report with each scan's metadata, vulnerability
     *    summary, full vulnerability list, and license list.
     *  - CSV: one flat vulnerability table where each row carries its scan's
     *    context columns (scan, target, project) so rows from different scans
     *    stay distinguishable in Excel.
     *
     * Scans the user cannot access are skipped silently rather than failing the
     * whole download.
     */
    async bulkExport(
        ids: string[],
        format: 'csv' | 'json',
        currentUser?: RequestUser,
    ): Promise<{ content: string; fileName: string; contentType: string }> {
        const uniqueIds = Array.from(new Set(ids)).filter(Boolean);
        if (uniqueIds.length === 0) {
            throw new BadRequestException('No scan ids were provided for export.');
        }

        const scans: Array<{
            id: string;
            target: string;
            project: string;
            status: string;
            createdAt: string;
            summary: { critical: number; high: number; medium: number; low: number; unknown: number; total: number };
            vulnerabilities: Array<Record<string, any>>;
            licenses: Array<Record<string, any>>;
        }> = [];

        for (const id of uniqueIds) {
            const scan = await this.prisma.scanResult.findUnique({
                where: { id },
                include: {
                    project: true,
                    summary: true,
                    vulnerabilities: { include: { vulnerability: true } },
                    packageLicenses: { include: { license: true } },
                },
            });
            if (!scan) continue;
            if (currentUser) {
                try {
                    assertProjectAccess(currentUser, scan.project);
                } catch {
                    continue; // skip scans the user cannot access
                }
            }

            scans.push({
                id: scan.id,
                target: this.getDisplayTargetName(scan),
                project: scan.project?.name || '-',
                status: scan.summary ? 'COMPLETED' : 'PENDING',
                createdAt: scan.createdAt.toISOString(),
                summary: {
                    critical: scan.summary?.critical ?? 0,
                    high: scan.summary?.high ?? 0,
                    medium: scan.summary?.medium ?? 0,
                    low: scan.summary?.low ?? 0,
                    unknown: scan.summary?.unknown ?? 0,
                    total: scan.summary?.totalVulns ?? 0,
                },
                vulnerabilities: scan.vulnerabilities.map((v) => ({
                    cveId: v.vulnerability?.cveId || '',
                    severity: v.vulnerability?.severity || '',
                    pkgName: v.pkgName,
                    installedVersion: v.pkgVersion,
                    fixedVersion: v.fixedVersion || '',
                    cvssScore: v.vulnerability?.cvssV3Score ?? '',
                    title: v.vulnerability?.title || '',
                    description: (v.vulnerability?.description || '').replace(/\r?\n/g, ' '),
                    status: v.status,
                })),
                licenses: scan.packageLicenses.map((l) => ({
                    pkgName: l.pkgName,
                    pkgVersion: l.pkgVersion,
                    licenseName: l.licenseName,
                    spdxId: l.license?.spdxId || '',
                    classification: l.license?.classification || '',
                    pkgPath: l.pkgPath || '',
                })),
            });
        }

        if (scans.length === 0) {
            throw new NotFoundException('None of the requested scans are available for export.');
        }

        const stamp = new Date().toISOString().slice(0, 10);

        if (format === 'json') {
            const report = {
                generatedAt: new Date().toISOString(),
                scanCount: scans.length,
                totals: scans.reduce(
                    (acc, s) => ({
                        critical: acc.critical + s.summary.critical,
                        high: acc.high + s.summary.high,
                        medium: acc.medium + s.summary.medium,
                        low: acc.low + s.summary.low,
                        unknown: acc.unknown + s.summary.unknown,
                        total: acc.total + s.summary.total,
                    }),
                    { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 },
                ),
                scans,
            };
            return {
                content: JSON.stringify(report, null, 2),
                fileName: `scans-export-${stamp}.json`,
                contentType: 'application/json',
            };
        }

        // CSV: flat vulnerability table with scan context columns.
        const headers = [
            'scan', 'target', 'project', 'scannedAt',
            'cveId', 'severity', 'pkgName', 'installedVersion', 'fixedVersion',
            'cvssScore', 'title', 'description', 'status',
        ];
        const rows: Array<Record<string, any>> = [];
        for (const s of scans) {
            if (s.vulnerabilities.length === 0) {
                // Still record the scan so "no vulnerabilities" is visible.
                rows.push({
                    scan: s.id, target: s.target, project: s.project, scannedAt: s.createdAt,
                    cveId: '', severity: '', pkgName: '', installedVersion: '', fixedVersion: '',
                    cvssScore: '', title: '(취약점 없음)', description: '', status: '',
                });
                continue;
            }
            for (const v of s.vulnerabilities) {
                rows.push({ scan: s.id, target: s.target, project: s.project, scannedAt: s.createdAt, ...v });
            }
        }

        return {
            content: this.toCsv(headers, rows),
            fileName: `scans-export-${stamp}.csv`,
            contentType: 'text/csv',
        };
    }

    /** Delete multiple scans, skipping ones the user cannot access. */
    async bulkDelete(ids: string[], currentUser?: RequestUser): Promise<{ deleted: number; failed: number }> {
        const uniqueIds = Array.from(new Set(ids)).filter(Boolean);
        let deleted = 0;
        let failed = 0;
        for (const id of uniqueIds) {
            try {
                await this.delete(id, currentUser);
                deleted++;
            } catch {
                failed++;
            }
        }
        return { deleted, failed };
    }

    private toCsv(headers: string[], rows: Array<Record<string, any>>): string {
        const escape = (value: any) => {
            const str = value === null || value === undefined ? '' : String(value);
            if (/[",\n]/.test(str)) {
                return `"${str.replace(/"/g, '""')}"`;
            }
            return str;
        };
        const lines = [headers.join(',')];
        for (const row of rows) {
            lines.push(headers.map((h) => escape(row[h])).join(','));
        }
        // Prepend BOM so Excel opens UTF-8 (Korean) correctly.
        return '﻿' + lines.join('\r\n');
    }

    // ===== Project aggregate recomputation (feature 6) =====

    /**
     * Recompute and return per-project vulnerability aggregates by summing the
     * latest scan per distinct artifact (imageRef) in each project. This fixes
     * the bug where a project only reflected its single most-recent scan and
     * scans on other artifacts were dropped from the aggregate.
     */
    async aggregateProjectVulnerabilities(projectIds: string[]): Promise<Map<string, { critical: number; high: number; medium: number; low: number; total: number; lastScanAt?: Date }>> {
        const result = new Map<string, { critical: number; high: number; medium: number; low: number; total: number; lastScanAt?: Date }>();
        if (projectIds.length === 0) return result;

        const scans = await this.prisma.scanResult.findMany({
            where: { projectId: { in: projectIds } },
            include: { summary: true },
            orderBy: { createdAt: 'desc' },
        });

        // For each project, keep only the latest scan per distinct imageRef.
        const seenArtifact = new Map<string, Set<string>>();
        for (const scan of scans) {
            const agg = result.get(scan.projectId) || { critical: 0, high: 0, medium: 0, low: 0, total: 0, lastScanAt: undefined as Date | undefined };
            if (!agg.lastScanAt || scan.createdAt > agg.lastScanAt) {
                agg.lastScanAt = scan.createdAt;
            }

            const artifactKey = scan.imageRef || scan.artifactName || scan.id;
            const seen = seenArtifact.get(scan.projectId) || new Set<string>();
            if (!seen.has(artifactKey)) {
                seen.add(artifactKey);
                seenArtifact.set(scan.projectId, seen);
                if (scan.summary) {
                    agg.critical += scan.summary.critical || 0;
                    agg.high += scan.summary.high || 0;
                    agg.medium += scan.summary.medium || 0;
                    agg.low += scan.summary.low || 0;
                    agg.total += scan.summary.totalVulns || 0;
                }
            }
            result.set(scan.projectId, agg);
        }
        return result;
    }

    /**
     * Compare two scans and return added/removed vulnerabilities
     */
    async compareScan(baseScanId: string, compareScanId: string, currentUser?: RequestUser) {
        // Get both scans with their vulnerabilities
        const [baseScan, compareScan] = await Promise.all([
            this.prisma.scanResult.findUnique({
                where: { id: baseScanId },
                include: {
                    summary: true,
                    vulnerabilities: {
                        include: {
                            vulnerability: true,
                        },
                    },
                },
            }),
            this.prisma.scanResult.findUnique({
                where: { id: compareScanId },
                include: {
                    summary: true,
                    vulnerabilities: {
                        include: {
                            vulnerability: true,
                        },
                    },
                },
            }),
        ]);

        if (!baseScan) {
            throw new NotFoundException(`Base scan ${baseScanId} not found`);
        }
        if (!compareScan) {
            throw new NotFoundException(`Compare scan ${compareScanId} not found`);
        }
        if (currentUser) {
            const [baseProject, compareProject] = await Promise.all([
                this.prisma.project.findUnique({ where: { id: baseScan.projectId } }),
                this.prisma.project.findUnique({ where: { id: compareScan.projectId } }),
            ]);
            assertProjectAccess(currentUser, baseProject);
            assertProjectAccess(currentUser, compareProject);
        }

        // Create sets of vulnerability hashes for comparison
        const baseVulnHashes = new Set(baseScan.vulnerabilities.map(v => v.vulnHash));
        const compareVulnHashes = new Set(compareScan.vulnerabilities.map(v => v.vulnHash));

        // Find added vulnerabilities (in compare but not in base)
        const added = compareScan.vulnerabilities
            .filter(v => !baseVulnHashes.has(v.vulnHash))
            .map(v => ({
                cveId: v.vulnerability.cveId,
                pkgName: v.pkgName,
                severity: v.vulnerability.severity,
                title: v.vulnerability.title || '',
                fixedVersion: v.fixedVersion,
            }));

        // Find removed vulnerabilities (in base but not in compare)
        const removed = baseScan.vulnerabilities
            .filter(v => !compareVulnHashes.has(v.vulnHash))
            .map(v => ({
                cveId: v.vulnerability.cveId,
                pkgName: v.pkgName,
                severity: v.vulnerability.severity,
                title: v.vulnerability.title || '',
                fixedVersion: v.fixedVersion,
            }));

        // Count unchanged
        const unchanged = baseScan.vulnerabilities.filter(v => compareVulnHashes.has(v.vulnHash)).length;

        return {
            baseScan: {
                id: baseScan.id,
                targetName: baseScan.imageRef || baseScan.artifactName || 'Unknown',
                date: baseScan.createdAt,
                totalVulnerabilities: baseScan.summary?.totalVulns || baseScan.vulnerabilities.length,
            },
            compareScan: {
                id: compareScan.id,
                targetName: compareScan.imageRef || compareScan.artifactName || 'Unknown',
                date: compareScan.createdAt,
                totalVulnerabilities: compareScan.summary?.totalVulns || compareScan.vulnerabilities.length,
            },
            added,
            removed,
            unchanged,
        };
    }
}
