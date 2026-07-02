import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export interface TimelineEvent {
    id: string;
    type: 'SCAN' | 'STATUS_CHANGE' | 'COMMENT' | 'EVIDENCE' | 'POLICY_VIOLATION';
    timestamp: Date;
    title: string;
    description?: string;
    metadata?: Record<string, unknown>;
    actor?: { id: string; name: string };
}

export interface VulnerabilityTimeline {
    cveId: string;
    vulnerabilityId: string;
    events: TimelineEvent[];
    firstSeen: Date;
    lastUpdated: Date;
}

@Injectable()
export class TimelineService {
    private readonly logger = new Logger(TimelineService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Get timeline for a specific vulnerability across a project
     */
    async getVulnerabilityTimeline(
        projectId: string,
        cveId: string,
    ): Promise<VulnerabilityTimeline | null> {
        // Get all scan vulnerabilities for this CVE in project
        const scanVulns = await this.prisma.scanVulnerability.findMany({
            where: {
                scanResult: { projectId },
                vulnerability: { cveId },
            },
            include: {
                scanResult: true,
                vulnerability: true,
                comments: {
                    include: { author: { select: { id: true, name: true } } },
                },
                assignee: { select: { id: true, name: true } },
            },
            orderBy: { createdAt: 'asc' },
        });

        if (scanVulns.length === 0) return null;

        const events: TimelineEvent[] = [];

        for (const scanVuln of scanVulns) {
            // Scan event
            events.push({
                id: `scan-${scanVuln.id}`,
                type: 'SCAN',
                timestamp: scanVuln.scanResult.createdAt,
                title: `Detected in scan`,
                description: `Found in ${scanVuln.scanResult.imageRef || 'scan'}`,
                metadata: {
                    scanResultId: scanVuln.scanResultId,
                    severity: scanVuln.vulnerability.severity,
                    status: scanVuln.status,
                },
            });

            // Comment events
            for (const comment of scanVuln.comments) {
                events.push({
                    id: `comment-${comment.id}`,
                    type: 'COMMENT',
                    timestamp: comment.createdAt,
                    title: 'Comment added',
                    description: comment.content.substring(0, 100),
                    actor: comment.author,
                });
            }
        }

        // Get workflow history (note: model may not exist until migration)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;
        const workflowHistory = (await prismaAny.vulnerabilityWorkflow?.findMany({
            where: {
                scanVulnerability: {
                    scanResult: { projectId },
                    vulnerability: { cveId },
                },
            },
            include: {
                changedBy: { select: { id: true, name: true } },
            },
            orderBy: { createdAt: 'asc' },
        })) || [];

        for (const wf of workflowHistory) {
            events.push({
                id: `workflow-${wf.id}`,
                type: 'STATUS_CHANGE',
                timestamp: wf.createdAt,
                title: `Status changed: ${wf.fromStatus} → ${wf.toStatus}`,
                description: wf.comment || undefined,
                actor: wf.changedBy,
            });
        }

        // Get fix evidence (note: model may not exist until migration)
        const evidence = (await prismaAny.fixEvidence?.findMany({
            where: {
                scanVulnerability: {
                    scanResult: { projectId },
                    vulnerability: { cveId },
                },
            },
            include: {
                createdBy: { select: { id: true, name: true } },
            },
            orderBy: { createdAt: 'asc' },
        })) || [];

        for (const ev of evidence) {
            events.push({
                id: `evidence-${ev.id}`,
                type: 'EVIDENCE',
                timestamp: ev.createdAt,
                title: `Evidence added: ${ev.evidenceType}`,
                description: ev.description || undefined,
                actor: ev.createdBy,
            });
        }

        // Sort all events by timestamp
        events.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

        return {
            cveId,
            vulnerabilityId: scanVulns[0].vulnerabilityId,
            events,
            firstSeen: events[0]?.timestamp || new Date(),
            lastUpdated: events[events.length - 1]?.timestamp || new Date(),
        };
    }

    /**
     * Get project activity timeline
     */
    async getProjectTimeline(
        projectId: string,
        limit = 50,
    ): Promise<TimelineEvent[]> {
        const events: TimelineEvent[] = [];

        // Recent scans
        const scans = await this.prisma.scanResult.findMany({
            where: { projectId },
            orderBy: { createdAt: 'desc' },
            take: 10,
            include: {
                _count: { select: { vulnerabilities: true } },
            },
        });

        for (const scan of scans) {
            events.push({
                id: `scan-${scan.id}`,
                type: 'SCAN',
                timestamp: scan.createdAt,
                title: `Scan completed: ${scan.imageRef || 'Unknown image'}`,
                description: `Found ${scan._count.vulnerabilities} vulnerabilities`,
                metadata: { scanId: scan.id },
            });
        }

        // Recent status changes (note: model may not exist until migration)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny2 = this.prisma as any;
        const workflows = (await prismaAny2.vulnerabilityWorkflow?.findMany({
            where: { scanVulnerability: { scanResult: { projectId } } },
            orderBy: { createdAt: 'desc' },
            take: 20,
            include: {
                changedBy: { select: { id: true, name: true } },
                scanVulnerability: {
                    include: { vulnerability: { select: { cveId: true } } },
                },
            },
        })) || [];

        for (const wf of workflows) {
            events.push({
                id: `workflow-${wf.id}`,
                type: 'STATUS_CHANGE',
                timestamp: wf.createdAt,
                title: `${wf.scanVulnerability.vulnerability.cveId}: ${wf.fromStatus} → ${wf.toStatus}`,
                actor: wf.changedBy,
            });
        }

        // Sort and limit
        return events
            .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
            .slice(0, limit);
    }
}
