import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';

export interface RiskScoreInput {
    cveId: string;
    cvssScore: number;
    severity: string;
    exploitAvailable?: boolean;
    projectId?: string;
}

export interface RiskScoreResult {
    cveId: string;
    baseScore: number;
    adjustedScore: number;
    factorBreakdown: {
        cvssComponent: number;
        exposureComponent: number;
        assetComponent: number;
        exploitComponent: number;
    };
    riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

@Injectable()
export class RiskScoreService {
    private readonly logger = new Logger(RiskScoreService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Calculate risk score for a vulnerability with customized weights
     */
    async calculateRiskScore(
        organizationId: string,
        input: RiskScoreInput,
    ): Promise<RiskScoreResult> {
        // Get organization's risk score configuration
        const config = await this.getRiskScoreConfig(organizationId);

        // Get asset criticality if project is specified
        const assetCriticality = input.projectId
            ? await this.getAssetCriticality(input.projectId)
            : null;

        // Calculate base CVSS component
        const cvssComponent = input.cvssScore * config.cvssWeight;

        // Calculate exposure component
        const exposureMultiplier = this.getExposureMultiplier(
            assetCriticality?.exposureLevel || 'INTERNAL',
        );
        const exposureComponent = exposureMultiplier * config.exposureWeight;

        // Calculate asset criticality component
        const assetMultiplier = this.getAssetMultiplier(
            assetCriticality?.criticalityLevel || 'MEDIUM',
        );
        const assetComponent = assetMultiplier * config.assetWeight;

        // Calculate exploit availability component
        const exploitComponent = input.exploitAvailable
            ? config.exploitWeight
            : 1.0;

        // Calculate adjusted score
        const adjustedScore = Math.min(
            10,
            (cvssComponent * exposureComponent * assetComponent * exploitComponent) / 10,
        );

        return {
            cveId: input.cveId,
            baseScore: input.cvssScore,
            adjustedScore: Math.round(adjustedScore * 100) / 100,
            factorBreakdown: {
                cvssComponent: Math.round(cvssComponent * 100) / 100,
                exposureComponent: Math.round(exposureComponent * 100) / 100,
                assetComponent: Math.round(assetComponent * 100) / 100,
                exploitComponent: Math.round(exploitComponent * 100) / 100,
            },
            riskLevel: this.getRiskLevel(adjustedScore),
        };
    }

    /**
     * Calculate risk scores for multiple vulnerabilities
     */
    async calculateBulkRiskScores(
        organizationId: string,
        inputs: RiskScoreInput[],
    ): Promise<RiskScoreResult[]> {
        const results: RiskScoreResult[] = [];

        for (const input of inputs) {
            const result = await this.calculateRiskScore(organizationId, input);
            results.push(result);
        }

        return results.sort((a, b) => b.adjustedScore - a.adjustedScore);
    }

    /**
     * Get or create risk score configuration for organization
     */
    async getRiskScoreConfig(organizationId: string) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        let config = await prismaAny.riskScoreConfig?.findUnique({
            where: { organizationId },
        });

        if (!config) {
            // Return default config
            return {
                exposureWeight: 1.0,
                assetWeight: 1.0,
                cvssWeight: 1.0,
                exploitWeight: 1.5,
                customFormula: null,
            };
        }

        return config;
    }

    /**
     * Update risk score configuration
     */
    async updateRiskScoreConfig(
        organizationId: string,
        data: {
            exposureWeight?: number;
            assetWeight?: number;
            cvssWeight?: number;
            exploitWeight?: number;
            customFormula?: string;
        },
    ) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        return prismaAny.riskScoreConfig?.upsert({
            where: { organizationId },
            create: {
                organizationId,
                ...data,
            },
            update: data,
        });
    }

    /**
     * Get asset criticality for a project
     */
    async getAssetCriticality(projectId: string) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        return prismaAny.assetCriticality?.findUnique({
            where: { projectId },
        });
    }

    /**
     * Update asset criticality for a project
     */
    async updateAssetCriticality(
        projectId: string,
        data: {
            criticalityLevel?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
            exposureLevel?: 'INTERNET' | 'DMZ' | 'INTERNAL' | 'ISOLATED';
            tags?: string[];
            notes?: string;
        },
    ) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        return prismaAny.assetCriticality?.upsert({
            where: { projectId },
            create: {
                projectId,
                ...data,
            },
            update: data,
        });
    }

    // Helper methods

    private getExposureMultiplier(exposureLevel: string): number {
        const multipliers: Record<string, number> = {
            INTERNET: 2.0,
            DMZ: 1.5,
            INTERNAL: 1.0,
            ISOLATED: 0.5,
        };
        return multipliers[exposureLevel] || 1.0;
    }

    private getAssetMultiplier(criticalityLevel: string): number {
        const multipliers: Record<string, number> = {
            CRITICAL: 2.0,
            HIGH: 1.5,
            MEDIUM: 1.0,
            LOW: 0.5,
        };
        return multipliers[criticalityLevel] || 1.0;
    }

    private getRiskLevel(score: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
        if (score >= 9.0) return 'CRITICAL';
        if (score >= 7.0) return 'HIGH';
        if (score >= 4.0) return 'MEDIUM';
        return 'LOW';
    }
}
