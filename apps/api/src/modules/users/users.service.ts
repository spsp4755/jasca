import {
    BadRequestException,
    ConflictException,
    ForbiddenException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { Role, RoleScope } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { PasswordPolicyService } from '../auth/services/password-policy.service';
import {
    normalizePermissionMatrix,
    resolvePermissionsForRoles,
} from '../../common/authorization/permissions';

type RequestUser = {
    id: string;
    organizationId?: string | null;
    roles?: Array<{ role: string } | string>;
};

@Injectable()
export class UsersService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly passwordPolicyService: PasswordPolicyService,
    ) { }

    async findAll(
        actor: RequestUser | undefined,
        organizationId?: string,
        options?: {
            limit?: number;
            offset?: number;
            search?: string;
            role?: string;
            status?: string;
        },
    ) {
        const scopedOrganizationId = this.resolveScopedOrganizationId(actor, organizationId);
        const where: Record<string, any> = {};

        if (scopedOrganizationId) {
            where.organizationId = scopedOrganizationId;
        }

        if (options?.search) {
            where.OR = [
                { name: { contains: options.search, mode: 'insensitive' } },
                { email: { contains: options.search, mode: 'insensitive' } },
            ];
        }

        if (options?.status) {
            where.isActive = options.status === 'ACTIVE';
        }

        if (options?.role) {
            where.roles = {
                some: {
                    role: options.role as Role,
                },
            };
        }

        const [users, total] = await Promise.all([
            this.prisma.user.findMany({
                where,
                include: {
                    roles: true,
                    organization: { select: { id: true, name: true } },
                    mfa: true,
                },
                orderBy: { createdAt: 'desc' },
                take: options?.limit || 25,
                skip: options?.offset || 0,
            }),
            this.prisma.user.count({ where }),
        ]);

        const permissionMatrix = await this.getPermissionMatrix();

        return {
            data: users.map((user) => this.transformUser(user, permissionMatrix)),
            total,
        };
    }

    async findById(id: string, actor?: RequestUser) {
        const user = await this.prisma.user.findUnique({
            where: { id },
            include: {
                roles: true,
                organization: { select: { id: true, name: true } },
                mfa: true,
            },
        });

        if (!user) {
            throw new NotFoundException('User not found');
        }

        this.assertUserScope(actor, user.organizationId, user.roles.map((role) => role.role), user.id);

        return this.transformUser(user, await this.getPermissionMatrix());
    }

    async findByEmail(email: string) {
        return this.prisma.user.findUnique({
            where: { email },
            include: { roles: true },
        });
    }

    async createUser(
        actor: RequestUser,
        data: { email: string; name: string; password: string; role?: string; status?: string; organizationId?: string },
    ) {
        const normalizedRole = this.normalizeRole(data.role);
        const targetOrganizationId = this.resolveTargetOrganizationId(actor, data.organizationId);

        if (!targetOrganizationId && normalizedRole !== 'SYSTEM_ADMIN') {
            throw new BadRequestException('organizationId is required for non-system users');
        }

        if (!this.isSystemAdmin(actor) && normalizedRole === 'SYSTEM_ADMIN') {
            throw new ForbiddenException('Only system admins can create system admins');
        }

        const existingUser = await this.prisma.user.findUnique({
            where: { email: data.email },
            select: { id: true },
        });

        if (existingUser) {
            throw new ConflictException('Email already registered');
        }

        const validation = await this.passwordPolicyService.validatePassword(
            data.password,
            targetOrganizationId || undefined,
        );
        if (!validation.isValid) {
            throw new BadRequestException(validation.errors.join(', '));
        }

        const passwordHash = await this.passwordPolicyService.hashPassword(data.password);
        const user = await this.prisma.user.create({
            data: {
                email: data.email,
                name: data.name,
                passwordHash,
                passwordChangedAt: new Date(),
                isActive: data.status !== 'INACTIVE',
                organizationId: targetOrganizationId || undefined,
                roles: {
                    create: {
                        role: normalizedRole,
                        scope: normalizedRole === 'SYSTEM_ADMIN' ? RoleScope.GLOBAL : RoleScope.ORGANIZATION,
                        scopeId: normalizedRole === 'SYSTEM_ADMIN' ? undefined : targetOrganizationId || undefined,
                    },
                },
            },
            include: {
                roles: true,
                organization: { select: { id: true, name: true } },
                mfa: true,
            },
        });

        return this.transformUser(user, await this.getPermissionMatrix());
    }

    async update(id: string, data: { name?: string; isActive?: boolean }) {
        return this.prisma.user.update({
            where: { id },
            data,
        });
    }

    async updateUser(
        actor: RequestUser,
        id: string,
        data: { name?: string; role?: string; status?: string; organizationId?: string },
    ) {
        const targetUser = await this.prisma.user.findUnique({
            where: { id },
            include: {
                roles: true,
                organization: { select: { id: true, name: true } },
                mfa: true,
            },
        });

        if (!targetUser) {
            throw new NotFoundException('User not found');
        }

        this.assertUserScope(actor, targetUser.organizationId, targetUser.roles.map((role) => role.role), targetUser.id);

        const normalizedRole = data.role ? this.normalizeRole(data.role) : undefined;
        if (!this.isSystemAdmin(actor) && normalizedRole === 'SYSTEM_ADMIN') {
            throw new ForbiddenException('Only system admins can assign system admin');
        }

        const targetOrganizationId = data.organizationId !== undefined
            ? this.resolveTargetOrganizationId(actor, data.organizationId)
            : targetUser.organizationId;

        const updateData: { name?: string; isActive?: boolean; organizationId?: string | null } = {};
        if (data.name !== undefined) {
            updateData.name = data.name;
        }
        if (data.status) {
            updateData.isActive = data.status === 'ACTIVE';
        }
        if (data.organizationId !== undefined) {
            updateData.organizationId = targetOrganizationId || null;
        }

        if (Object.keys(updateData).length > 0) {
            await this.prisma.user.update({
                where: { id },
                data: updateData,
            });
        }

        if (normalizedRole) {
            await this.prisma.userRole.deleteMany({ where: { userId: id } });
            await this.prisma.userRole.create({
                data: {
                    userId: id,
                    role: normalizedRole,
                    scope: normalizedRole === 'SYSTEM_ADMIN' ? RoleScope.GLOBAL : RoleScope.ORGANIZATION,
                    scopeId: normalizedRole === 'SYSTEM_ADMIN' ? undefined : targetOrganizationId || undefined,
                },
            });
        }

        return this.findById(id, actor);
    }

    async deleteUser(actor: RequestUser, id: string) {
        if (actor.id === id) {
            throw new BadRequestException('You cannot delete your own account');
        }

        const targetUser = await this.prisma.user.findUnique({
            where: { id },
            include: { roles: true },
        });

        if (!targetUser) {
            throw new NotFoundException('User not found');
        }

        this.assertUserScope(actor, targetUser.organizationId, targetUser.roles.map((role) => role.role), targetUser.id);

        await this.prisma.userRole.deleteMany({ where: { userId: id } });
        return this.prisma.user.delete({
            where: { id },
        });
    }

    async assignRole(userId: string, role: string, scope: string, scopeId?: string) {
        return this.prisma.userRole.create({
            data: {
                userId,
                role: role as Role,
                scope: scope as RoleScope,
                scopeId,
            },
        });
    }

    async removeRole(userId: string, roleId: string) {
        return this.prisma.userRole.delete({
            where: { id: roleId },
        });
    }

    private notificationSettings: Map<string, { emailAlerts: boolean; criticalOnly: boolean; weeklyDigest: boolean }> = new Map();

    async getNotificationSettings(userId: string): Promise<{ emailAlerts: boolean; criticalOnly: boolean; weeklyDigest: boolean }> {
        const settings = this.notificationSettings.get(userId);
        if (!settings) {
            return {
                emailAlerts: true,
                criticalOnly: false,
                weeklyDigest: true,
            };
        }
        return settings;
    }

    async updateNotificationSettings(
        userId: string,
        dto: { emailAlerts?: boolean; criticalOnly?: boolean; weeklyDigest?: boolean },
    ): Promise<{ emailAlerts: boolean; criticalOnly: boolean; weeklyDigest: boolean }> {
        const currentSettings = await this.getNotificationSettings(userId);
        const updatedSettings = {
            emailAlerts: dto.emailAlerts ?? currentSettings.emailAlerts,
            criticalOnly: dto.criticalOnly ?? currentSettings.criticalOnly,
            weeklyDigest: dto.weeklyDigest ?? currentSettings.weeklyDigest,
        };
        this.notificationSettings.set(userId, updatedSettings);
        return updatedSettings;
    }

    private normalizeRole(role?: string): Role {
        const normalizedRole = (role || 'VIEWER') as Role;
        const validRoles = new Set<Role>([
            Role.SYSTEM_ADMIN,
            Role.ORG_ADMIN,
            Role.SECURITY_ADMIN,
            Role.PROJECT_ADMIN,
            Role.DEVELOPER,
            Role.VIEWER,
        ]);

        if (!validRoles.has(normalizedRole)) {
            throw new BadRequestException(`Invalid role: ${role}`);
        }

        return normalizedRole;
    }

    private resolveScopedOrganizationId(actor?: RequestUser, organizationId?: string): string | undefined {
        if (!actor || this.isSystemAdmin(actor)) {
            return organizationId;
        }

        if (!actor.organizationId) {
            return organizationId;
        }

        if (organizationId && organizationId !== actor.organizationId) {
            throw new ForbiddenException('You can only access users in your organization');
        }

        return actor.organizationId;
    }

    private resolveTargetOrganizationId(actor: RequestUser, organizationId?: string): string | undefined {
        if (this.isSystemAdmin(actor)) {
            return organizationId;
        }

        if (!actor.organizationId) {
            throw new ForbiddenException('Organization-scoped admin account is required');
        }

        if (organizationId && organizationId !== actor.organizationId) {
            throw new ForbiddenException('You can only manage users in your organization');
        }

        return actor.organizationId;
    }

    private assertUserScope(
        actor: RequestUser | undefined,
        targetOrganizationId?: string | null,
        targetRoles: Role[] = [],
        targetUserId?: string,
    ) {
        if (!actor || this.isSystemAdmin(actor)) {
            return;
        }

        if (targetRoles.includes(Role.SYSTEM_ADMIN)) {
            throw new ForbiddenException('You cannot manage system admin accounts');
        }

        if (actor.id === targetUserId) {
            return;
        }

        if (actor.organizationId && actor.organizationId !== targetOrganizationId) {
            throw new ForbiddenException('You can only manage users in your organization');
        }
    }

    private isSystemAdmin(actor?: RequestUser): boolean {
        const roles = (actor?.roles || []).map((role) => (typeof role === 'string' ? role : role.role));
        return roles.includes(Role.SYSTEM_ADMIN);
    }

    private async getPermissionMatrix() {
        const setting = await this.prisma.systemSettings.findUnique({
            where: { key: 'permissions' },
            select: { value: true },
        });

        return normalizePermissionMatrix(setting?.value);
    }

    private transformUser(user: any, permissionMatrix: ReturnType<typeof normalizePermissionMatrix>) {
        const roles = (user.roles || []).map((role: any) => role.role || role);
        const permissions = resolvePermissionsForRoles(roles, permissionMatrix);

        return {
            id: user.id,
            email: user.email,
            name: user.name,
            role: roles[0] || Role.VIEWER,
            roles,
            permissions,
            status: user.isActive ? 'ACTIVE' : 'INACTIVE',
            mfaEnabled: !!user.mfa?.isEnabled,
            organizationId: user.organizationId,
            organization: user.organization,
            createdAt: user.createdAt,
            lastLoginAt: user.lastLoginAt,
        };
    }
}
