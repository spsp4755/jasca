import { Injectable, NotFoundException, ConflictException, ForbiddenException } from '@nestjs/common';
import { Role } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { CreateProjectDto } from './dto/create-project.dto';

type RequestUser = {
    id: string;
    organizationId?: string | null;
    roles?: Array<{ role: string } | string>;
};

@Injectable()
export class ProjectsService {
    constructor(private readonly prisma: PrismaService) { }

    async findAll(actor: RequestUser | undefined, organizationId?: string, options?: {
        limit?: number;
        offset?: number;
        search?: string;
        sortBy?: 'name' | 'createdAt' | 'riskLevel';
        sortOrder?: 'asc' | 'desc';
        riskLevel?: string;
    }) {
        const where: any = {};
        const scopedOrganizationId = this.resolveScopedOrganizationId(actor, organizationId);
        if (scopedOrganizationId) {
            where.organizationId = scopedOrganizationId;
        }
        // Search filter for name and slug
        if (options?.search) {
            where.OR = [
                { name: { contains: options.search, mode: 'insensitive' } },
                { slug: { contains: options.search, mode: 'insensitive' } },
            ];
        }

        // Build dynamic orderBy
        const sortOrder = options?.sortOrder || 'desc';
        let orderBy: any;
        switch (options?.sortBy) {
            case 'name':
                orderBy = { name: sortOrder };
                break;
            case 'createdAt':
            default:
                orderBy = { createdAt: sortOrder };
                break;
        }

        const projects = await this.prisma.project.findMany({
            where,
            include: {
                organization: true,
                scanResults: {
                    include: { summary: true },
                    orderBy: { createdAt: 'desc' },
                    take: 1,
                },
                _count: {
                    select: { scanResults: true },
                },
            },
            orderBy,
            take: options?.limit || 50,
            skip: options?.offset || 0,
        });

        // Get total count for pagination
        const total = await this.prisma.project.count({ where });

        // Transform projects to include stats like findById does
        const data = projects.map(project => {
            const latestScan = project.scanResults[0];
            const summary = latestScan?.summary;
            const stats = {
                totalScans: project._count.scanResults,
                lastScanAt: latestScan?.createdAt?.toISOString(),
                vulnerabilities: {
                    critical: summary?.critical || 0,
                    high: summary?.high || 0,
                    medium: summary?.medium || 0,
                    low: summary?.low || 0,
                    total: summary?.totalVulns || 0,
                },
            };

            // Calculate risk level based on vulnerabilities
            let riskLevel = 'NONE';
            if (stats.vulnerabilities.critical > 0) riskLevel = 'CRITICAL';
            else if (stats.vulnerabilities.high > 0) riskLevel = 'HIGH';
            else if (stats.vulnerabilities.medium > 0) riskLevel = 'MEDIUM';
            else if (stats.vulnerabilities.low > 0) riskLevel = 'LOW';

            return {
                ...project,
                scanResults: undefined, // Don't include full scan results
                stats,
                riskLevel,
            };
        });

        // Filter by risk level if specified (post-filter since it's computed)
        const filteredData = options?.riskLevel 
            ? data.filter(p => p.riskLevel === options.riskLevel)
            : data;

        return { data: filteredData, total };
    }

    async findById(id: string, actor?: RequestUser) {
        const project = await this.prisma.project.findUnique({
            where: { id },
            include: {
                organization: true,
                registries: true,
                scanResults: {
                    include: { summary: true },
                    orderBy: { createdAt: 'desc' },
                    take: 1,
                },
                _count: {
                    select: { scanResults: true },
                },
            },
        });

        if (!project) {
            throw new NotFoundException('Project not found');
        }

        this.assertProjectScope(actor, project.organizationId);

        // Calculate stats from the latest scan result
        const latestScan = project.scanResults[0];
        const summary = latestScan?.summary;
        const stats = {
            totalScans: project._count.scanResults,
            lastScanAt: latestScan?.createdAt?.toISOString(),
            vulnerabilities: {
                critical: summary?.critical || 0,
                high: summary?.high || 0,
                medium: summary?.medium || 0,
                low: summary?.low || 0,
                total: summary?.totalVulns || 0,
            },
        };

        // Calculate risk level based on vulnerabilities
        let riskLevel = 'NONE';
        if (stats.vulnerabilities.critical > 0) riskLevel = 'CRITICAL';
        else if (stats.vulnerabilities.high > 0) riskLevel = 'HIGH';
        else if (stats.vulnerabilities.medium > 0) riskLevel = 'MEDIUM';
        else if (stats.vulnerabilities.low > 0) riskLevel = 'LOW';

        return {
            ...project,
            scanResults: undefined, // Don't include full scan results
            stats,
            riskLevel,
        };
    }

    async create(actor: RequestUser, organizationId: string, dto: CreateProjectDto) {
        const scopedOrganizationId = this.resolveScopedOrganizationId(actor, organizationId);
        if (!scopedOrganizationId) {
            throw new ForbiddenException('organizationId is required');
        }

        const existing = await this.prisma.project.findFirst({
            where: {
                organizationId: scopedOrganizationId,
                slug: dto.slug,
            },
        });

        if (existing) {
            throw new ConflictException('Project slug already exists in this organization');
        }

        return this.prisma.project.create({
            data: {
                name: dto.name,
                slug: dto.slug,
                description: dto.description,
                organizationId: scopedOrganizationId,
            },
        });
    }

    async update(actor: RequestUser, id: string, data: Partial<CreateProjectDto>) {
        await this.findById(id, actor);

        return this.prisma.project.update({
            where: { id },
            data,
        });
    }

    async delete(actor: RequestUser, id: string) {
        await this.findById(id, actor);

        return this.prisma.project.delete({
            where: { id },
        });
    }

    async getVulnerabilityTrend(projectId: string, days: number, actor?: RequestUser) {
        await this.findById(projectId, actor);

        // Get scan results with summaries for the last N days
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - days);

        const scanResults = await this.prisma.scanResult.findMany({
            where: {
                projectId,
                createdAt: { gte: startDate },
            },
            include: { summary: true },
            orderBy: { createdAt: 'asc' },
        });

        // Group by date and aggregate
        const trendMap = new Map<string, { critical: number; high: number; medium: number; low: number; total: number }>();

        for (const scan of scanResults) {
            const dateKey = scan.createdAt.toISOString().split('T')[0];
            const existing = trendMap.get(dateKey) || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };

            if (scan.summary) {
                existing.critical += scan.summary.critical || 0;
                existing.high += scan.summary.high || 0;
                existing.medium += scan.summary.medium || 0;
                existing.low += scan.summary.low || 0;
                existing.total += scan.summary.totalVulns || 0;
            }

            trendMap.set(dateKey, existing);
        }

        // Convert to array and fill missing dates
        const trend = [];
        for (let i = 0; i < days; i++) {
            const date = new Date();
            date.setDate(date.getDate() - (days - 1 - i));
            const dateKey = date.toISOString().split('T')[0];
            trend.push({
                date: dateKey,
                ...(trendMap.get(dateKey) || { critical: 0, high: 0, medium: 0, low: 0, total: 0 }),
            });
        }
        // Return just the trend array (frontend expects array directly)
        return trend;
    }

    private isSystemAdmin(actor?: RequestUser) {
        const roles = (actor?.roles || []).map((role) => (typeof role === 'string' ? role : role.role));
        return roles.includes(Role.SYSTEM_ADMIN);
    }

    private resolveScopedOrganizationId(actor?: RequestUser, organizationId?: string) {
        if (!actor || this.isSystemAdmin(actor)) {
            return organizationId;
        }

        if (!actor.organizationId) {
            return organizationId;
        }

        if (organizationId && organizationId !== actor.organizationId) {
            throw new ForbiddenException('You can only access projects in your organization');
        }

        return actor.organizationId;
    }

    private assertProjectScope(actor: RequestUser | undefined, organizationId: string) {
        if (!actor || this.isSystemAdmin(actor)) {
            return;
        }

        if (actor.organizationId && actor.organizationId !== organizationId) {
            throw new ForbiddenException('You can only access projects in your organization');
        }
    }
}

