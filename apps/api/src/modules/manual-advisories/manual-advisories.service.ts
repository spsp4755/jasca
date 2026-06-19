import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, Severity } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import {
    RequestUser,
    assertOrganizationAccess,
    assertProjectAccess,
    getScopedOrganizationIds,
    isSystemAdmin,
} from '../../common/authz/access-control';
import { ParsedVulnerability } from '../scans/services/trivy-parser.service';

export interface ManualAdvisoryDto {
    advisoryId: string;
    cveId?: string;
    title: string;
    description?: string;
    severity: Severity;
    packageName: string;
    affectedVersionRange?: string;
    fixedVersion?: string;
    remediation?: string;
    references?: string[];
    isActive?: boolean;
    organizationId?: string;
    projectId?: string;
}

interface PackageCandidate {
    name: string;
    version: string;
    path?: string;
}

@Injectable()
export class ManualAdvisoriesService {
    constructor(private readonly prisma: PrismaService) { }

    async findAll(currentUser: RequestUser, filters?: { organizationId?: string; projectId?: string; isActive?: boolean }) {
        const where = await this.buildAccessWhere(currentUser, filters);

        return this.prisma.manualAdvisory.findMany({
            where,
            include: {
                organization: { select: { id: true, name: true } },
                project: { select: { id: true, name: true } },
                createdBy: { select: { id: true, name: true, email: true } },
            },
            orderBy: { updatedAt: 'desc' },
        });
    }

    async create(dto: ManualAdvisoryDto, currentUser: RequestUser) {
        await this.assertWritableScope(dto, currentUser);
        this.validateDto(dto);

        return this.prisma.manualAdvisory.create({
            data: {
                advisoryId: dto.advisoryId.trim(),
                cveId: this.blankToUndefined(dto.cveId),
                title: dto.title.trim(),
                description: this.blankToUndefined(dto.description),
                severity: dto.severity,
                packageName: dto.packageName.trim(),
                affectedVersionRange: dto.affectedVersionRange?.trim() || '*',
                fixedVersion: this.blankToUndefined(dto.fixedVersion),
                remediation: this.blankToUndefined(dto.remediation),
                references: this.normalizeReferences(dto.references),
                isActive: dto.isActive ?? true,
                organizationId: this.blankToUndefined(dto.organizationId),
                projectId: this.blankToUndefined(dto.projectId),
                createdById: currentUser?.id,
            },
        });
    }

    async update(id: string, dto: Partial<ManualAdvisoryDto>, currentUser: RequestUser) {
        const existing = await this.prisma.manualAdvisory.findUnique({
            where: { id },
            include: { project: true },
        });
        if (!existing) {
            throw new NotFoundException('Manual advisory not found');
        }

        await this.assertExistingWritableScope(existing, currentUser);
        const nextScope = {
            organizationId: dto.organizationId ?? existing.organizationId ?? undefined,
            projectId: dto.projectId ?? existing.projectId ?? undefined,
        };
        await this.assertWritableScope(nextScope, currentUser);

        if (dto.advisoryId || dto.title || dto.packageName || dto.severity) {
            this.validateDto({
                advisoryId: dto.advisoryId ?? existing.advisoryId,
                title: dto.title ?? existing.title,
                packageName: dto.packageName ?? existing.packageName,
                severity: dto.severity ?? existing.severity,
            } as ManualAdvisoryDto);
        }

        return this.prisma.manualAdvisory.update({
            where: { id },
            data: {
                advisoryId: dto.advisoryId?.trim(),
                cveId: dto.cveId === undefined ? undefined : this.blankToNull(dto.cveId),
                title: dto.title?.trim(),
                description: dto.description === undefined ? undefined : this.blankToNull(dto.description),
                severity: dto.severity,
                packageName: dto.packageName?.trim(),
                affectedVersionRange: dto.affectedVersionRange?.trim() || undefined,
                fixedVersion: dto.fixedVersion === undefined ? undefined : this.blankToNull(dto.fixedVersion),
                remediation: dto.remediation === undefined ? undefined : this.blankToNull(dto.remediation),
                references: dto.references === undefined ? undefined : this.normalizeReferences(dto.references),
                isActive: dto.isActive,
                organizationId: dto.organizationId === undefined ? undefined : this.blankToNull(dto.organizationId),
                projectId: dto.projectId === undefined ? undefined : this.blankToNull(dto.projectId),
            },
        });
    }

    async remove(id: string, currentUser: RequestUser) {
        const existing = await this.prisma.manualAdvisory.findUnique({
            where: { id },
            include: { project: true },
        });
        if (!existing) {
            throw new NotFoundException('Manual advisory not found');
        }

        await this.assertExistingWritableScope(existing, currentUser);
        return this.prisma.manualAdvisory.delete({ where: { id } });
    }

    async getManualVulnerabilitiesForScan(projectId: string, rawResult: any): Promise<ParsedVulnerability[]> {
        const project = await this.prisma.project.findUnique({
            where: { id: projectId },
            select: { id: true, organizationId: true },
        });
        if (!project) {
            return [];
        }

        const advisories = await this.prisma.manualAdvisory.findMany({
            where: {
                isActive: true,
                OR: [
                    { projectId: project.id },
                    { projectId: null, organizationId: project.organizationId },
                    { projectId: null, organizationId: null },
                ],
            },
            orderBy: [{ severity: 'asc' }, { updatedAt: 'desc' }],
        });

        if (advisories.length === 0) {
            return [];
        }

        const packages = this.extractPackages(rawResult);
        const vulnerabilities: ParsedVulnerability[] = [];
        const seen = new Set<string>();

        for (const advisory of advisories) {
            for (const pkg of packages) {
                if (!this.packageMatches(advisory.packageName, pkg.name)) continue;
                if (!this.versionMatches(pkg.version, advisory.affectedVersionRange)) continue;

                const cveId = advisory.cveId || `MANUAL-${advisory.advisoryId}`;
                const key = `${cveId}:${pkg.name}:${pkg.version}`;
                if (seen.has(key)) continue;
                seen.add(key);

                vulnerabilities.push({
                    cveId,
                    title: `[수동 Advisory] ${advisory.title}`,
                    description: advisory.description || advisory.remediation || undefined,
                    severity: advisory.severity,
                    references: advisory.references,
                    cweIds: [],
                    pkgName: pkg.name,
                    pkgVersion: pkg.version,
                    fixedVersion: advisory.fixedVersion || undefined,
                    pkgPath: pkg.path,
                    layer: {
                        source: 'manual-advisory',
                        advisoryId: advisory.advisoryId,
                        affectedVersionRange: advisory.affectedVersionRange,
                    },
                });
            }
        }

        return vulnerabilities;
    }

    private async buildAccessWhere(currentUser: RequestUser, filters?: { organizationId?: string; projectId?: string; isActive?: boolean }): Promise<Prisma.ManualAdvisoryWhereInput> {
        const where: Prisma.ManualAdvisoryWhereInput = {};
        if (filters?.isActive !== undefined) where.isActive = filters.isActive;
        if (filters?.projectId) where.projectId = filters.projectId;
        if (filters?.organizationId) where.organizationId = filters.organizationId;

        if (isSystemAdmin(currentUser)) {
            return where;
        }

        const organizationIds = getScopedOrganizationIds(currentUser) || [];
        if (organizationIds.length === 0) {
            return { ...where, id: '__no_access__' };
        }

        where.OR = [
            { organizationId: { in: organizationIds } },
            { project: { organizationId: { in: organizationIds } } },
            { organizationId: null, projectId: null },
        ];

        return where;
    }

    private validateDto(dto: ManualAdvisoryDto) {
        if (!dto.advisoryId?.trim()) throw new BadRequestException('advisoryId is required');
        if (!dto.title?.trim()) throw new BadRequestException('title is required');
        if (!dto.packageName?.trim()) throw new BadRequestException('packageName is required');
        if (!dto.severity) throw new BadRequestException('severity is required');
    }

    private async assertWritableScope(dto: { organizationId?: string | null; projectId?: string | null }, currentUser: RequestUser) {
        if (isSystemAdmin(currentUser)) return;

        if (dto.projectId) {
            const project = await this.prisma.project.findUnique({ where: { id: dto.projectId } });
            if (!project) throw new BadRequestException('Project not found');
            assertProjectAccess(currentUser, project);
            return;
        }

        if (dto.organizationId) {
            assertOrganizationAccess(currentUser, dto.organizationId);
            return;
        }

        throw new BadRequestException('Only SYSTEM_ADMIN can create global manual advisories');
    }

    private async assertExistingWritableScope(existing: { organizationId?: string | null; projectId?: string | null; project?: { id: string; organizationId: string } | null }, currentUser: RequestUser) {
        if (isSystemAdmin(currentUser)) return;
        if (existing.projectId && existing.project) {
            assertProjectAccess(currentUser, existing.project);
            return;
        }
        if (existing.organizationId) {
            assertOrganizationAccess(currentUser, existing.organizationId);
            return;
        }
        throw new BadRequestException('Only SYSTEM_ADMIN can change global manual advisories');
    }

    private extractPackages(rawResult: any): PackageCandidate[] {
        const packages = new Map<string, PackageCandidate>();
        const results = Array.isArray(rawResult?.Results) ? rawResult.Results : [];

        for (const result of results) {
            for (const pkg of result.Packages || []) {
                const name = pkg.Name || pkg.PkgName || pkg.ID;
                const version = pkg.Version || pkg.InstalledVersion;
                if (!name || !version) continue;
                packages.set(`${name}:${version}:${result.Target || ''}`, {
                    name,
                    version,
                    path: pkg.Path || result.Target,
                });
            }

            for (const vuln of result.Vulnerabilities || []) {
                const name = vuln.PkgName;
                const version = vuln.InstalledVersion;
                if (!name || !version) continue;
                packages.set(`${name}:${version}:${vuln.PkgPath || result.Target || ''}`, {
                    name,
                    version,
                    path: vuln.PkgPath || result.Target,
                });
            }
        }

        return Array.from(packages.values());
    }

    private packageMatches(rulePackage: string, packageName: string): boolean {
        const rule = rulePackage.trim().toLowerCase();
        const name = packageName.trim().toLowerCase();
        if (rule === '*' || rule === name) return true;
        if (rule.endsWith('*')) return name.startsWith(rule.slice(0, -1));
        return false;
    }

    private versionMatches(installedVersion: string, range: string): boolean {
        const normalizedRange = (range || '*').trim();
        if (!normalizedRange || normalizedRange === '*') return true;

        if (/^[^\s]+-[^\s]+$/.test(normalizedRange) && !normalizedRange.startsWith('-')) {
            const [min, max] = normalizedRange.split('-', 2);
            return this.compareVersions(installedVersion, min) >= 0 && this.compareVersions(installedVersion, max) <= 0;
        }

        const expressions = normalizedRange.split(/[,\s]+/).filter(Boolean);
        return expressions.every((expression) => this.versionExpressionMatches(installedVersion, expression));
    }

    private versionExpressionMatches(version: string, expression: string): boolean {
        const match = expression.match(/^(<=|>=|<|>|=)?(.+)$/);
        if (!match) return false;

        const operator = match[1] || '=';
        const target = match[2];
        const compared = this.compareVersions(version, target);

        switch (operator) {
            case '<':
                return compared < 0;
            case '<=':
                return compared <= 0;
            case '>':
                return compared > 0;
            case '>=':
                return compared >= 0;
            default:
                return compared === 0;
        }
    }

    private compareVersions(left: string, right: string): number {
        const leftParts = this.toVersionParts(left);
        const rightParts = this.toVersionParts(right);
        const length = Math.max(leftParts.length, rightParts.length);

        for (let index = 0; index < length; index += 1) {
            const leftPart = leftParts[index] || 0;
            const rightPart = rightParts[index] || 0;
            if (leftPart > rightPart) return 1;
            if (leftPart < rightPart) return -1;
        }

        return 0;
    }

    private toVersionParts(version: string): number[] {
        return String(version)
            .replace(/^[^\d]*/, '')
            .split(/[^0-9]+/)
            .filter(Boolean)
            .map((part) => Number(part));
    }

    private normalizeReferences(references?: string[]): string[] {
        return (references || [])
            .flatMap((reference) => String(reference).split(/\r?\n/))
            .map((reference) => reference.trim())
            .filter(Boolean);
    }

    private blankToUndefined(value?: string | null): string | undefined {
        const normalized = value?.trim();
        return normalized || undefined;
    }

    private blankToNull(value?: string | null): string | null {
        const normalized = value?.trim();
        return normalized || null;
    }
}
