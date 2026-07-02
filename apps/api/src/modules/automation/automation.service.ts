import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export interface ScheduledScanConfig {
    projectId: string;
    cronExpression: string;
    enabled: boolean;
    lastRun?: Date;
    nextRun?: Date;
}

export interface AlertThreshold {
    organizationId: string;
    criticalThreshold: number;
    highThreshold: number;
    newVulnAlert: boolean;
    zeroAlertEnabled: boolean;
}

export interface AlertEvent {
    type: 'THRESHOLD_BREACH' | 'NEW_VULNERABILITY' | 'ZERO_DAY';
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    projectId: string;
    projectName: string;
    message: string;
    timestamp: Date;
}

@Injectable()
export class AutomationService {
    private readonly logger = new Logger(AutomationService.name);

    // In-memory storage for demo (would be in DB in production)
    private scheduledScans: Map<string, ScheduledScanConfig> = new Map();
    private alertThresholds: Map<string, AlertThreshold> = new Map();

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Configure scheduled scan for a project
     */
    async configureScheduledScan(
        projectId: string,
        cronExpression: string,
        enabled = true,
    ): Promise<ScheduledScanConfig> {
        const config: ScheduledScanConfig = {
            projectId,
            cronExpression,
            enabled,
            nextRun: this.calculateNextRun(cronExpression),
        };

        this.scheduledScans.set(projectId, config);
        this.logger.log(`Scheduled scan configured for project ${projectId}: ${cronExpression}`);

        return config;
    }

    /**
     * Get scheduled scan config for a project
     */
    getScheduledScanConfig(projectId: string): ScheduledScanConfig | undefined {
        return this.scheduledScans.get(projectId);
    }

    /**
     * Configure alert thresholds for an organization
     */
    async configureAlertThresholds(
        organizationId: string,
        thresholds: Partial<AlertThreshold>,
    ): Promise<AlertThreshold> {
        const existing = this.alertThresholds.get(organizationId) || {
            organizationId,
            criticalThreshold: 1,
            highThreshold: 5,
            newVulnAlert: true,
            zeroAlertEnabled: true,
        };

        const updated: AlertThreshold = {
            ...existing,
            ...thresholds,
        };

        this.alertThresholds.set(organizationId, updated);
        return updated;
    }

    /**
     * Check if scan results breach any thresholds
     */
    async checkThresholdBreach(scanResultId: string): Promise<AlertEvent[]> {
        const scan = await this.prisma.scanResult.findUnique({
            where: { id: scanResultId },
            include: {
                project: { include: { organization: true } },
                vulnerabilities: { include: { vulnerability: true } },
            },
        });

        if (!scan) return [];

        const thresholds = this.alertThresholds.get(scan.project.organizationId);
        if (!thresholds) return [];

        const alerts: AlertEvent[] = [];
        let criticalCount = 0;
        let highCount = 0;

        for (const sv of scan.vulnerabilities) {
            if (sv.vulnerability.severity === 'CRITICAL') criticalCount++;
            else if (sv.vulnerability.severity === 'HIGH') highCount++;

            // Check for zero-day
            if (thresholds.zeroAlertEnabled && sv.vulnerability.isZeroDay) {
                alerts.push({
                    type: 'ZERO_DAY',
                    severity: 'CRITICAL',
                    projectId: scan.projectId,
                    projectName: scan.project.name,
                    message: `Zero-day vulnerability detected: ${sv.vulnerability.cveId}`,
                    timestamp: new Date(),
                });
            }
        }

        // Check thresholds
        if (criticalCount >= thresholds.criticalThreshold) {
            alerts.push({
                type: 'THRESHOLD_BREACH',
                severity: 'CRITICAL',
                projectId: scan.projectId,
                projectName: scan.project.name,
                message: `Critical threshold breached: ${criticalCount} critical vulnerabilities (threshold: ${thresholds.criticalThreshold})`,
                timestamp: new Date(),
            });
        }

        if (highCount >= thresholds.highThreshold) {
            alerts.push({
                type: 'THRESHOLD_BREACH',
                severity: 'HIGH',
                projectId: scan.projectId,
                projectName: scan.project.name,
                message: `High threshold breached: ${highCount} high vulnerabilities (threshold: ${thresholds.highThreshold})`,
                timestamp: new Date(),
            });
        }

        return alerts;
    }

    /**
     * Get all scheduled scans
     */
    getAllScheduledScans(): ScheduledScanConfig[] {
        return Array.from(this.scheduledScans.values());
    }

    // Helper to calculate next run (simplified)
    private calculateNextRun(cronExpression: string): Date {
        // Simplified: just add 24 hours for daily schedules
        const next = new Date();
        next.setHours(next.getHours() + 24);
        return next;
    }
}
