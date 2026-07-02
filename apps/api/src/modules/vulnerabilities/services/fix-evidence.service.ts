import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';

type EvidenceType = 'PR_LINK' | 'COMMIT' | 'IMAGE_TAG_CHANGE' | 'PACKAGE_UPGRADE' | 'PATCH_APPLIED' | 'CONFIG_CHANGE' | 'WORKAROUND' | 'DOCUMENTATION' | 'OTHER';

export interface CreateEvidenceDto {
    scanVulnerabilityId: string;
    evidenceType: EvidenceType;
    url?: string;
    description?: string;
    previousValue?: string;
    newValue?: string;
    attachments?: {
        fileName: string;
        fileType: string;
        fileSize: number;
        storageKey?: string;
    }[];
}

export interface EvidenceRecord {
    id: string;
    evidenceType: EvidenceType;
    url?: string;
    description?: string;
    previousValue?: string;
    newValue?: string;
    createdBy: { id: string; name: string; email: string };
    createdAt: Date;
}

@Injectable()
export class FixEvidenceService {
    private readonly logger = new Logger(FixEvidenceService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Create fix evidence for a vulnerability
     */
    async createEvidence(
        userId: string,
        dto: CreateEvidenceDto,
    ): Promise<EvidenceRecord> {
        // Verify vulnerability exists
        const scanVuln = await this.prisma.scanVulnerability.findUnique({
            where: { id: dto.scanVulnerabilityId },
        });

        if (!scanVuln) {
            throw new BadRequestException('Vulnerability not found');
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        const evidence = await prismaAny.fixEvidence?.create({
            data: {
                scanVulnerabilityId: dto.scanVulnerabilityId,
                evidenceType: dto.evidenceType,
                url: dto.url,
                description: dto.description,
                previousValue: dto.previousValue,
                newValue: dto.newValue,
                attachments: dto.attachments ? JSON.stringify(dto.attachments) : null,
                createdById: userId,
            },
            include: {
                createdBy: { select: { id: true, name: true, email: true } },
            },
        });

        this.logger.log(
            `Created ${dto.evidenceType} evidence for vulnerability ${dto.scanVulnerabilityId}`,
        );

        return evidence;
    }

    /**
     * Get all evidence for a vulnerability
     */
    async getEvidenceForVulnerability(
        scanVulnerabilityId: string,
    ): Promise<EvidenceRecord[]> {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        return (
            prismaAny.fixEvidence?.findMany({
                where: { scanVulnerabilityId },
                include: {
                    createdBy: { select: { id: true, name: true, email: true } },
                },
                orderBy: { createdAt: 'desc' },
            }) || []
        );
    }

    /**
     * Create PR link evidence
     */
    async addPrLink(
        userId: string,
        scanVulnerabilityId: string,
        prUrl: string,
        description?: string,
    ): Promise<EvidenceRecord> {
        return this.createEvidence(userId, {
            scanVulnerabilityId,
            evidenceType: 'PR_LINK',
            url: prUrl,
            description: description || `Fix PR: ${prUrl}`,
        });
    }

    /**
     * Create package upgrade evidence
     */
    async addPackageUpgrade(
        userId: string,
        scanVulnerabilityId: string,
        previousVersion: string,
        newVersion: string,
        description?: string,
    ): Promise<EvidenceRecord> {
        return this.createEvidence(userId, {
            scanVulnerabilityId,
            evidenceType: 'PACKAGE_UPGRADE',
            previousValue: previousVersion,
            newValue: newVersion,
            description:
                description || `Upgraded from ${previousVersion} to ${newVersion}`,
        });
    }

    /**
     * Create image tag change evidence
     */
    async addImageTagChange(
        userId: string,
        scanVulnerabilityId: string,
        previousTag: string,
        newTag: string,
        description?: string,
    ): Promise<EvidenceRecord> {
        return this.createEvidence(userId, {
            scanVulnerabilityId,
            evidenceType: 'IMAGE_TAG_CHANGE',
            previousValue: previousTag,
            newValue: newTag,
            description: description || `Changed image tag from ${previousTag} to ${newTag}`,
        });
    }

    /**
     * Delete evidence
     */
    async deleteEvidence(evidenceId: string, userId: string): Promise<void> {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        const evidence = await prismaAny.fixEvidence?.findUnique({
            where: { id: evidenceId },
        });

        if (!evidence) {
            throw new BadRequestException('Evidence not found');
        }

        if (evidence.createdById !== userId) {
            throw new BadRequestException('Can only delete your own evidence');
        }

        await prismaAny.fixEvidence?.delete({
            where: { id: evidenceId },
        });
    }

    /**
     * Get evidence summary for a project
     */
    async getEvidenceSummary(projectId: string): Promise<{
        total: number;
        byType: Record<string, number>;
        recentEvidence: EvidenceRecord[];
    }> {
        const scans = await this.prisma.scanResult.findMany({
            where: { projectId },
            select: { id: true },
        });

        const scanIds = scans.map((s: { id: string }) => s.id);

        const vulns = await this.prisma.scanVulnerability.findMany({
            where: { scanResultId: { in: scanIds } },
            select: { id: true },
        });

        const vulnIds = vulns.map((v: { id: string }) => v.id);

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        const evidence =
            (await prismaAny.fixEvidence?.findMany({
                where: { scanVulnerabilityId: { in: vulnIds } },
                include: {
                    createdBy: { select: { id: true, name: true, email: true } },
                },
                orderBy: { createdAt: 'desc' },
            })) || [];

        const byType: Record<string, number> = {};
        for (const e of evidence) {
            byType[e.evidenceType] = (byType[e.evidenceType] || 0) + 1;
        }

        return {
            total: evidence.length,
            byType,
            recentEvidence: evidence.slice(0, 10),
        };
    }
}
