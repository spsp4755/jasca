import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export interface ScannerHealth {
    scannerId: string;
    scannerName: string;
    status: 'HEALTHY' | 'DEGRADED' | 'DOWN';
    lastHeartbeat: Date;
    scanQueueSize: number;
    avgScanDuration: number;
    errorRate: number;
}

export interface SystemStatus {
    status: 'OPERATIONAL' | 'DEGRADED' | 'OUTAGE';
    components: {
        name: string;
        status: 'UP' | 'DOWN' | 'DEGRADED';
        latency?: number;
        message?: string;
    }[];
    lastUpdated: Date;
}

export interface OperationalMetrics {
    scansToday: number;
    scansThisWeek: number;
    avgScanDuration: number;
    totalVulnerabilitiesFound: number;
    pendingScans: number;
    failedScans: number;
}

@Injectable()
export class OperationsService {
    private readonly logger = new Logger(OperationsService.name);

    // In-memory scanner health tracking (would use Redis in production)
    private scannerHealth: Map<string, ScannerHealth> = new Map();

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Get system status overview
     */
    async getSystemStatus(): Promise<SystemStatus> {
        const dbStatus = await this.checkDatabase();
        const scannerStatuses = this.getScannerStatuses();

        const components = [
            {
                name: 'Database',
                status: dbStatus.healthy ? 'UP' as const : 'DOWN' as const,
                latency: dbStatus.latency,
            },
            {
                name: 'API Server',
                status: 'UP' as const,
                latency: 0,
            },
            ...scannerStatuses,
        ];

        const hasDown = components.some(c => c.status === 'DOWN');
        const hasDegraded = components.some(c => c.status === 'DEGRADED');

        return {
            status: hasDown ? 'OUTAGE' : hasDegraded ? 'DEGRADED' : 'OPERATIONAL',
            components,
            lastUpdated: new Date(),
        };
    }

    /**
     * Get operational metrics
     */
    async getOperationalMetrics(): Promise<OperationalMetrics> {
        const now = new Date();
        const startOfDay = new Date(now.setHours(0, 0, 0, 0));
        const startOfWeek = new Date(now);
        startOfWeek.setDate(startOfWeek.getDate() - 7);

        const [scansToday, scansThisWeek, totalVulns] = await Promise.all([
            this.prisma.scanResult.count({
                where: { createdAt: { gte: startOfDay } },
            }),
            this.prisma.scanResult.count({
                where: { createdAt: { gte: startOfWeek } },
            }),
            this.prisma.scanVulnerability.count(),
        ]);

        return {
            scansToday,
            scansThisWeek,
            avgScanDuration: 0, // Would calculate from scan metadata
            totalVulnerabilitiesFound: totalVulns,
            pendingScans: 0,
            failedScans: 0,
        };
    }

    /**
     * Register scanner heartbeat
     */
    registerScannerHeartbeat(
        scannerId: string,
        scannerName: string,
        queueSize: number,
        avgDuration: number,
        errorRate: number,
    ): void {
        const health: ScannerHealth = {
            scannerId,
            scannerName,
            status: errorRate > 0.5 ? 'DOWN' : errorRate > 0.1 ? 'DEGRADED' : 'HEALTHY',
            lastHeartbeat: new Date(),
            scanQueueSize: queueSize,
            avgScanDuration: avgDuration,
            errorRate,
        };

        this.scannerHealth.set(scannerId, health);
        this.logger.debug(`Scanner heartbeat: ${scannerName} (${health.status})`);
    }

    /**
     * Get all scanner health statuses
     */
    getAllScannerHealth(): ScannerHealth[] {
        const now = new Date();
        const staleThreshold = 5 * 60 * 1000; // 5 minutes

        return Array.from(this.scannerHealth.values()).map(health => {
            const isStale = now.getTime() - health.lastHeartbeat.getTime() > staleThreshold;
            return {
                ...health,
                status: isStale ? 'DOWN' : health.status,
            };
        });
    }

    /**
     * Get scan performance statistics
     */
    async getScanPerformance(days = 7): Promise<{
        dailyScans: { date: string; count: number }[];
        scansByProject: { projectName: string; count: number }[];
        averageVulnsPerScan: number;
    }> {
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - days);

        const scans = await this.prisma.scanResult.findMany({
            where: { createdAt: { gte: startDate } },
            include: {
                project: { select: { name: true } },
                _count: { select: { vulnerabilities: true } },
            },
        });

        // Group by date
        const byDate = new Map<string, number>();
        const byProject = new Map<string, number>();
        let totalVulns = 0;

        for (const scan of scans) {
            const date = scan.createdAt.toISOString().split('T')[0];
            byDate.set(date, (byDate.get(date) || 0) + 1);
            byProject.set(scan.project.name, (byProject.get(scan.project.name) || 0) + 1);
            totalVulns += scan._count.vulnerabilities;
        }

        return {
            dailyScans: Array.from(byDate.entries()).map(([date, count]) => ({ date, count })),
            scansByProject: Array.from(byProject.entries())
                .map(([projectName, count]) => ({ projectName, count }))
                .sort((a, b) => b.count - a.count),
            averageVulnsPerScan: scans.length > 0 ? totalVulns / scans.length : 0,
        };
    }

    // Helper methods

    private async checkDatabase(): Promise<{ healthy: boolean; latency: number }> {
        const start = Date.now();
        try {
            await this.prisma.$queryRaw`SELECT 1`;
            return { healthy: true, latency: Date.now() - start };
        } catch {
            return { healthy: false, latency: -1 };
        }
    }

    private getScannerStatuses(): { name: string; status: 'UP' | 'DOWN' | 'DEGRADED' }[] {
        return this.getAllScannerHealth().map(h => ({
            name: `Scanner: ${h.scannerName}`,
            status: h.status === 'HEALTHY' ? 'UP' : h.status === 'DOWN' ? 'DOWN' : 'DEGRADED',
        }));
    }
}
