import { BadRequestException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { PolicyAction, PolicyRuleType } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { CreatePolicyDto, CreatePolicyRuleDto } from './dto/create-policy.dto';
import {
    RequestUser,
    assertOrganizationAccess,
    assertOrganizationManager,
    assertProjectAccess,
    assertProjectManager,
    getScopedOrganizationIds,
    getUserRoles,
    isSystemAdmin,
} from '../../common/authz/access-control';

type IncomingPolicyRule = CreatePolicyRuleDto & {
    operator?: string;
    value?: string;
    condition?: string;
    conditions?: any;
    sendNotification?: boolean;
};

@Injectable()
export class PoliciesService {
    constructor(private readonly prisma: PrismaService) { }

    private getScopedProjectIds(user: RequestUser): string[] {
        return getUserRoles(user)
            .filter((role) => role.scope === 'PROJECT' && role.scopeId)
            .map((role) => role.scopeId as string);
    }

    private buildPolicyAccessWhere(user: RequestUser, organizationId?: string, projectId?: string) {
        if (projectId) {
            return { projectId };
        }

        if (organizationId) {
            return {
                OR: [
                    { organizationId, projectId: null },
                    { project: { organizationId } },
                ],
            };
        }

        if (isSystemAdmin(user)) {
            return {};
        }

        const organizationIds = getScopedOrganizationIds(user) || [];
        const projectIds = this.getScopedProjectIds(user);
        const filters: any[] = [];

        if (organizationIds.length > 0) {
            filters.push({ organizationId: { in: organizationIds } });
            filters.push({ project: { organizationId: { in: organizationIds } } });
        }
        if (projectIds.length > 0) {
            filters.push({ projectId: { in: projectIds } });
        }

        return filters.length > 0 ? { OR: filters } : { id: '__no_access__' };
    }

    private async assertRequestedScopeAccess(user: RequestUser, organizationId?: string, projectId?: string) {
        if (projectId) {
            const project = await this.prisma.project.findUnique({ where: { id: projectId } });
            if (!project) throw new NotFoundException('Project not found');
            assertProjectAccess(user, project);
            return;
        }

        if (organizationId) {
            assertOrganizationAccess(user, organizationId);
        }
    }

    private assertPolicyManager(policy: any, user?: RequestUser) {
        if (!user) return;

        if (policy.project) {
            assertProjectManager(user, policy.project, ['ORG_ADMIN', 'PROJECT_ADMIN', 'SECURITY_ADMIN']);
            return;
        }

        if (policy.projectId) {
            throw new BadRequestException('Policy project relation is required for permission checks');
        }

        if (policy.organizationId) {
            assertOrganizationManager(user, policy.organizationId, ['ORG_ADMIN', 'SECURITY_ADMIN']);
            return;
        }

        if (!isSystemAdmin(user)) {
            throw new ForbiddenException('Only system administrators can manage global policies');
        }
    }

    private normalizeAction(action: string): PolicyAction {
        if (action === 'AUDIT' || action === 'NOTIFY') return PolicyAction.INFO;
        if (Object.values(PolicyAction).includes(action as PolicyAction)) return action as PolicyAction;
        throw new BadRequestException(`Invalid policy action: ${action}`);
    }

    private splitValues(value?: string): string[] {
        return (value || '')
            .split(/[\n,]+/)
            .map((item) => item.trim())
            .filter(Boolean);
    }

    private normalizeRule(rule: IncomingPolicyRule, index = 0) {
        const rawRuleType = String(rule.ruleType);
        const action = this.normalizeAction(String(rule.action));
        const operator = rule.operator || 'EQUALS';
        const rawValue = rule.value ?? rule.condition;

        let ruleType: PolicyRuleType;
        let conditions = rule.conditions ?? {};

        switch (rawRuleType) {
            case 'SEVERITY':
                ruleType = PolicyRuleType.SEVERITY_THRESHOLD;
                conditions = { severity: this.splitValues(rawValue).map((value) => value.toUpperCase()) };
                break;
            case 'CVE_ID':
                ruleType = PolicyRuleType.CVE_BLOCKLIST;
                conditions = operator === 'EQUALS'
                    ? { cveIds: this.splitValues(rawValue).map((value) => value.toUpperCase()) }
                    : { cvePatterns: this.splitValues(rawValue), patternMode: operator };
                break;
            case 'PACKAGE':
                ruleType = PolicyRuleType.PACKAGE_BLOCKLIST;
                conditions = operator === 'EQUALS'
                    ? { packageNames: this.splitValues(rawValue) }
                    : { packagePatterns: this.splitValues(rawValue), patternMode: operator };
                break;
            case 'CVSS_SCORE':
                ruleType = PolicyRuleType.CVSS_THRESHOLD;
                conditions = { cvssScore: { gte: Number(rawValue) } };
                break;
            case 'AGE_DAYS':
                ruleType = PolicyRuleType.CVE_AGE;
                conditions = { cveAge: { days: Number(rawValue) } };
                break;
            case 'LICENSE':
            case 'FIX_AVAILABLE':
                ruleType = PolicyRuleType.CUSTOM;
                conditions = { legacyType: rawRuleType, operator, value: rawValue };
                break;
            default:
                if (!Object.values(PolicyRuleType).includes(rawRuleType as PolicyRuleType)) {
                    throw new BadRequestException(`Invalid policy rule type: ${rawRuleType}`);
                }
                ruleType = rawRuleType as PolicyRuleType;
                conditions = this.normalizeNativeRuleConditions(ruleType, conditions, rawValue, operator);
                break;
        }

        if (ruleType === PolicyRuleType.CVSS_THRESHOLD && !Number.isFinite(conditions?.cvssScore?.gte)) {
            throw new BadRequestException('CVSS policy rule requires a numeric threshold');
        }

        if (ruleType === PolicyRuleType.CVE_AGE && !Number.isFinite(conditions?.cveAge?.days)) {
            throw new BadRequestException('CVE age policy rule requires a numeric day value');
        }

        return {
            ruleType,
            conditions,
            action,
            message: rule.message,
            priority: rule.priority ?? index,
            sendNotification: Boolean(rule.sendNotification),
        };
    }

    private normalizeNativeRuleConditions(
        ruleType: PolicyRuleType,
        conditions: any,
        rawValue?: string,
        operator = 'EQUALS',
    ) {
        if (conditions && Object.keys(conditions).length > 0) {
            return conditions;
        }

        switch (ruleType) {
            case PolicyRuleType.SEVERITY_THRESHOLD:
                return { severity: this.splitValues(rawValue).map((value) => value.toUpperCase()) };
            case PolicyRuleType.CVE_BLOCKLIST:
                return operator === 'EQUALS'
                    ? { cveIds: this.splitValues(rawValue).map((value) => value.toUpperCase()) }
                    : { cvePatterns: this.splitValues(rawValue), patternMode: operator };
            case PolicyRuleType.PACKAGE_BLOCKLIST:
                return operator === 'EQUALS'
                    ? { packageNames: this.splitValues(rawValue) }
                    : { packagePatterns: this.splitValues(rawValue), patternMode: operator };
            case PolicyRuleType.CVSS_THRESHOLD:
                return { cvssScore: { gte: Number(rawValue) } };
            case PolicyRuleType.CVE_AGE:
                return { cveAge: { days: Number(rawValue) } };
            default:
                return conditions || {};
        }
    }

    private async resolvePolicyScope(dto: Partial<CreatePolicyDto>, user?: RequestUser) {
        if (dto.projectId) {
            const project = await this.prisma.project.findUnique({ where: { id: dto.projectId } });
            if (!project) throw new NotFoundException('Project not found');
            if (user) assertProjectManager(user, project, ['ORG_ADMIN', 'PROJECT_ADMIN', 'SECURITY_ADMIN']);
            return { organizationId: project.organizationId, projectId: project.id };
        }

        const organizationId = dto.organizationId || user?.organizationId;
        if (!organizationId) {
            throw new BadRequestException('organizationId or projectId is required for policy scope');
        }

        if (user) {
            assertOrganizationManager(user, organizationId, ['ORG_ADMIN', 'SECURITY_ADMIN']);
        }

        return { organizationId, projectId: null };
    }

    async findAll(currentUser: RequestUser, organizationId?: string, projectId?: string) {
        await this.assertRequestedScopeAccess(currentUser, organizationId, projectId);

        const where = this.buildPolicyAccessWhere(currentUser, organizationId, projectId);

        return this.prisma.policy.findMany({
            where,
            include: {
                rules: { orderBy: { priority: 'desc' } },
                organization: true,
                project: true,
                _count: { select: { exceptions: true } },
            },
            orderBy: { createdAt: 'desc' },
        });
    }

    async findById(id: string, currentUser?: RequestUser) {
        const policy = await this.prisma.policy.findUnique({
            where: { id },
            include: {
                rules: { orderBy: { priority: 'desc' } },
                exceptions: {
                    include: {
                        requestedBy: { select: { id: true, name: true, email: true } },
                        approvedBy: { select: { id: true, name: true, email: true } },
                    },
                },
                organization: true,
                project: true,
            },
        });

        if (!policy) {
            throw new NotFoundException('Policy not found');
        }

        if (currentUser) {
            if (policy.project) {
                assertProjectAccess(currentUser, policy.project);
            } else if (policy.organizationId) {
                assertOrganizationAccess(currentUser, policy.organizationId);
            } else if (!isSystemAdmin(currentUser)) {
                throw new ForbiddenException('You do not have access to this policy');
            }
        }

        return policy;
    }

    async create(dto: CreatePolicyDto, currentUser?: RequestUser) {
        const scope = await this.resolvePolicyScope(dto, currentUser);
        const normalizedRules = dto.rules?.map((rule, index) => this.normalizeRule(rule as IncomingPolicyRule, index));

        return this.prisma.policy.create({
            data: {
                name: dto.name,
                description: dto.description,
                isActive: dto.isActive ?? true,
                organizationId: scope.organizationId,
                projectId: scope.projectId,
                rules: normalizedRules
                    ? {
                        create: normalizedRules,
                    }
                    : undefined,
            },
            include: { rules: true, organization: true, project: true },
        });
    }

    async update(id: string, data: Partial<CreatePolicyDto>, currentUser?: RequestUser) {
        const existing = await this.findById(id, currentUser);
        this.assertPolicyManager(existing, currentUser);

        const scope = (data.organizationId !== undefined || data.projectId !== undefined)
            ? await this.resolvePolicyScope(data, currentUser)
            : undefined;

        const normalizedRules = data.rules?.map((rule, index) => this.normalizeRule(rule as IncomingPolicyRule, index));

        return this.prisma.$transaction(async (tx) => {
            if (normalizedRules) {
                await tx.policyRule.deleteMany({ where: { policyId: id } });
            }

            return tx.policy.update({
                where: { id },
                data: {
                    name: data.name,
                    description: data.description,
                    isActive: data.isActive,
                    organizationId: scope?.organizationId,
                    projectId: scope?.projectId,
                    rules: normalizedRules
                        ? { create: normalizedRules }
                        : undefined,
                },
                include: { rules: { orderBy: { priority: 'desc' } }, organization: true, project: true },
            });
        });
    }

    async addRule(policyId: string, rule: CreatePolicyRuleDto, currentUser?: RequestUser) {
        const policy = await this.findById(policyId, currentUser);
        this.assertPolicyManager(policy, currentUser);

        return this.prisma.policyRule.create({
            data: {
                policyId,
                ...this.normalizeRule(rule as IncomingPolicyRule),
            },
        });
    }

    async removeRule(ruleId: string, currentUser?: RequestUser) {
        const rule = await this.prisma.policyRule.findUnique({
            where: { id: ruleId },
            include: { policy: { include: { project: true } } },
        });

        if (!rule) {
            throw new NotFoundException('Policy rule not found');
        }

        this.assertPolicyManager(rule.policy, currentUser);
        return this.prisma.policyRule.delete({ where: { id: ruleId } });
    }

    async delete(id: string, currentUser?: RequestUser) {
        const policy = await this.findById(id, currentUser);
        this.assertPolicyManager(policy, currentUser);
        return this.prisma.policy.delete({ where: { id } });
    }

    // Exception management
    async findExceptions(currentUser: RequestUser, status?: string) {
        const where: any = {};
        if (status) {
            where.status = status.toUpperCase();
        }

        const policyWhere = this.buildPolicyAccessWhere(currentUser);
        where.policy = policyWhere;

        return this.prisma.policyException.findMany({
            where,
            include: {
                policy: { select: { id: true, name: true, organizationId: true, projectId: true } },
                requestedBy: { select: { id: true, name: true, email: true } },
                approvedBy: { select: { id: true, name: true, email: true } },
            },
            orderBy: { createdAt: 'desc' },
        });
    }

    async requestException(data: {
        policyId: string;
        exceptionType: string;
        targetValue: string;
        reason: string;
        requestedById: string;
        expiresAt?: Date;
    }, currentUser?: RequestUser) {
        await this.findById(data.policyId, currentUser);

        return this.prisma.policyException.create({
            data: {
                policyId: data.policyId,
                exceptionType: data.exceptionType as any,
                targetValue: data.targetValue,
                reason: data.reason,
                requestedById: data.requestedById,
                expiresAt: data.expiresAt,
                status: 'PENDING',
            },
        });
    }

    async approveException(id: string, approvedById: string, currentUser?: RequestUser) {
        const exception = await this.prisma.policyException.findUnique({
            where: { id },
            include: { policy: { include: { project: true } } },
        });

        if (!exception) throw new NotFoundException('Policy exception not found');
        this.assertPolicyManager(exception.policy, currentUser);

        return this.prisma.policyException.update({
            where: { id },
            data: {
                status: 'APPROVED',
                approvedById,
            },
        });
    }

    async rejectException(id: string, approvedById: string, currentUser?: RequestUser) {
        const exception = await this.prisma.policyException.findUnique({
            where: { id },
            include: { policy: { include: { project: true } } },
        });

        if (!exception) throw new NotFoundException('Policy exception not found');
        this.assertPolicyManager(exception.policy, currentUser);

        return this.prisma.policyException.update({
            where: { id },
            data: {
                status: 'REJECTED',
                approvedById,
            },
        });
    }
}
