import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { CreateProjectDto } from './dto/create-project.dto';
import {
    RequestUser,
    assertOrganizationManager,
    assertProjectAccess,
    assertProjectManager,
    getScopedOrganizationIds,
    getUserRoles,
    isSystemAdmin,
} from '../../common/authz/access-control';

@Injectable()
export class ProjectsService {
    constructor(private readonly prisma: PrismaService) { }

    /**
     * Aggregate vulnerability counts for a set of projects by summing the latest
     * scan per distinct artifact (imageRef) within each project. Previously the
     * project view only reflected the single most-recent scan, so vulnerabilities
     * from scans on other artifacts of the same project were dropped from the
     * aggregate. (Bug fix: project-level aggregation.)
     */
    private async computeProjectAggregates(projectIds: string[]) {
        const result = new Map<string, { critical: number; high: number; medium: number; low: number; total: number; lastScanAt?: Date }>();
        if (projectIds.length === 0) return result;

        const scans = await this.prisma.scanResult.findMany({
            where: { projectId: { in: projectIds } },
            include: { summary: true },
            orderBy: { createdAt: 'desc' },
        });

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

    private buildProjectAccessWhere(currentUser: RequestUser, organizationId?: string) {
        if (isSystemAdmin(currentUser)) {
            return organizationId ? { organizationId } : {};
        }

        const organizationIds = getScopedOrganizationIds(currentUser) || [];
        const projectIds = getUserRoles(currentUser)
            .filter((role) => role.scope === 'PROJECT' && role.scopeId)
            .map((role) => role.scopeId as string);

        const accessFilters: any[] = [];
        if (organizationIds.length > 0) accessFilters.push({ organizationId: { in: organizationIds } });
        if (projectIds.length > 0) accessFilters.push({ id: { in: projectIds } });

        if (accessFilters.length === 0) {
            return { id: '__no_access__' };
        }

        const accessWhere = { OR: accessFilters };
        if (organizationId) {
            return { AND: [{ organizationId }, accessWhere] };
        }

        return accessWhere;
    }

    async findAll(currentUser: RequestUser, organizationId?: string, options?: {
        limit?: number;
        offset?: number;
        search?: string;
        sortBy?: 'name' | 'createdAt' | 'riskLevel';
        sortOrder?: 'asc' | 'desc';
        riskLevel?: string;
    }) {
        const where: any = this.buildProjectAccessWhere(currentUser, organizationId);
        // Search filter for name and slug
        if (options?.search) {
            const searchWhere = {
                OR: [
                    { name: { contains: options.search, mode: 'insensitive' } },
                    { slug: { contains: options.search, mode: 'insensitive' } },
                ],
            };
            where.AND = where.AND ? [...where.AND, searchWhere] : [searchWhere];
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

        // Aggregate vulnerabilities across all scans (latest per artifact) per project.
        const aggregates = await this.computeProjectAggregates(projects.map((p) => p.id));

        // Transform projects to include stats like findById does
        const data = projects.map(project => {
            const aggregate = aggregates.get(project.id);
            const stats = {
                totalScans: project._count.scanResults,
                lastScanAt: (aggregate?.lastScanAt || project.scanResults[0]?.createdAt)?.toISOString(),
                vulnerabilities: {
                    critical: aggregate?.critical || 0,
                    high: aggregate?.high || 0,
                    medium: aggregate?.medium || 0,
                    low: aggregate?.low || 0,
                    total: aggregate?.total || 0,
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

    async findById(id: string, currentUser?: RequestUser) {
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

        if (currentUser) {
            assertProjectAccess(currentUser, project);
        }

        // Aggregate vulnerabilities across all scans (latest per artifact).
        const aggregates = await this.computeProjectAggregates([project.id]);
        const aggregate = aggregates.get(project.id);
        const stats = {
            totalScans: project._count.scanResults,
            lastScanAt: (aggregate?.lastScanAt || project.scanResults[0]?.createdAt)?.toISOString(),
            vulnerabilities: {
                critical: aggregate?.critical || 0,
                high: aggregate?.high || 0,
                medium: aggregate?.medium || 0,
                low: aggregate?.low || 0,
                total: aggregate?.total || 0,
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

    async create(organizationId: string | undefined, dto: CreateProjectDto, currentUser?: RequestUser) {
        const resolvedOrganizationId = organizationId || currentUser?.organizationId;
        if (!resolvedOrganizationId) {
            throw new BadRequestException('organizationId is required to create a project');
        }

        if (currentUser) {
            assertOrganizationManager(currentUser, resolvedOrganizationId, ['ORG_ADMIN']);
        }

        const existing = await this.prisma.project.findFirst({
            where: {
                organizationId: resolvedOrganizationId,
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
                organizationId: resolvedOrganizationId,
            },
        });
    }

    async update(id: string, data: Partial<CreateProjectDto>, currentUser?: RequestUser) {
        const project = await this.prisma.project.findUnique({ where: { id } });
        if (!project) {
            throw new NotFoundException('Project not found');
        }
        if (currentUser) {
            assertProjectManager(currentUser, project, ['ORG_ADMIN', 'PROJECT_ADMIN']);
        }

        return this.prisma.project.update({
            where: { id },
            data,
        });
    }

    async delete(id: string, currentUser?: RequestUser) {
        const project = await this.prisma.project.findUnique({ where: { id } });
        if (!project) {
            throw new NotFoundException('Project not found');
        }
        if (currentUser) {
            assertProjectManager(currentUser, project, ['ORG_ADMIN']);
        }

        return this.prisma.project.delete({
            where: { id },
        });
    }

    async getVulnerabilityTrend(projectId: string, days: number, currentUser?: RequestUser) {
        if (currentUser) {
            await this.findById(projectId, currentUser);
        }

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
}

