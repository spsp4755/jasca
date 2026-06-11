import { BadRequestException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, Role } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../../prisma/prisma.service';
import {
    RequestUser,
    canAccessOrganization,
    canManageOrganization,
    getScopedOrganizationIds,
    isSystemAdmin,
} from '../../common/authz/access-control';

type ManagedUser = Prisma.UserGetPayload<{
    include: {
        roles: true;
        organization: { select: { id: true; name: true } };
        mfa: true;
    };
}>;

@Injectable()
export class UsersService {
    constructor(private readonly prisma: PrismaService) { }

    private readonly validRoles = ['SYSTEM_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN', 'PROJECT_ADMIN', 'DEVELOPER', 'VIEWER'];
    private readonly rolePriority: Role[] = [
        'SYSTEM_ADMIN',
        'ORG_ADMIN',
        'SECURITY_ADMIN',
        'PROJECT_ADMIN',
        'DEVELOPER',
        'VIEWER',
    ];
    private readonly bcryptRounds = 12;

    private getPrimaryRole(roles: ManagedUser['roles']) {
        return [...roles].sort(
            (a, b) => this.rolePriority.indexOf(a.role) - this.rolePriority.indexOf(b.role),
        )[0];
    }

    private formatManagedUser(user: ManagedUser) {
        const primaryRole = this.getPrimaryRole(user.roles);

        return {
            id: user.id,
            email: user.email,
            name: user.name,
            role: primaryRole?.role || 'VIEWER',
            roleScope: primaryRole?.scope || null,
            roleScopeId: primaryRole?.scopeId || null,
            roles: user.roles.map((role) => ({
                id: role.id,
                role: role.role,
                scope: role.scope,
                scopeId: role.scopeId,
                createdAt: role.createdAt,
            })),
            status: user.isActive ? 'ACTIVE' : 'INACTIVE',
            mfaEnabled: !!user.mfa?.isEnabled,
            organizationId: user.organizationId,
            organization: user.organization,
            createdAt: user.createdAt,
            lastLoginAt: user.lastLoginAt,
        };
    }

    private resolveOrganizationForRole(
        currentUser: RequestUser | undefined,
        requestedOrganizationId: string | undefined,
        role: string,
    ) {
        if (role === 'SYSTEM_ADMIN') {
            if (currentUser && !isSystemAdmin(currentUser)) {
                throw new ForbiddenException('Only system administrators can assign SYSTEM_ADMIN');
            }
            return null;
        }

        const scopedOrganizationIds = getScopedOrganizationIds(currentUser);
        const organizationId = requestedOrganizationId || (
            scopedOrganizationIds && scopedOrganizationIds.length === 1 ? scopedOrganizationIds[0] : undefined
        );

        if (!organizationId) {
            throw new BadRequestException('organizationId is required for organization-scoped roles');
        }

        if (currentUser && !canManageOrganization(currentUser, organizationId, ['ORG_ADMIN'])) {
            throw new ForbiddenException('You do not have permission to manage this organization');
        }

        return organizationId;
    }

    async findAll(currentUser: RequestUser, organizationId?: string, options?: {
        limit?: number;
        offset?: number;
        search?: string;
        role?: string;
        status?: string;
    }) {
        const where: any = {};
        const scopedOrganizationIds = getScopedOrganizationIds(currentUser);

        if (organizationId) {
            if (!canAccessOrganization(currentUser, organizationId)) {
                throw new ForbiddenException('You do not have access to this organization');
            }
            where.organizationId = organizationId;
        } else if (scopedOrganizationIds) {
            where.organizationId = scopedOrganizationIds.length > 0
                ? { in: scopedOrganizationIds }
                : null;
        }

        // Search filter for name and email
        if (options?.search) {
            where.OR = [
                { name: { contains: options.search, mode: 'insensitive' } },
                { email: { contains: options.search, mode: 'insensitive' } },
            ];
        }
        // Status filter
        if (options?.status) {
            where.isActive = options.status === 'ACTIVE';
        }
        if (options?.role) {
            if (!this.validRoles.includes(options.role)) {
                throw new BadRequestException(`Invalid role: ${options.role}`);
            }
            where.roles = { some: { role: options.role as any } };
        }

        const users = await this.prisma.user.findMany({
            where,
            include: { 
                roles: true, 
                organization: { select: { id: true, name: true } },
                mfa: true,
            },
            orderBy: { createdAt: 'desc' },
            take: options?.limit || 25,
            skip: options?.offset || 0,
        });

        // Get total count for pagination
        const total = await this.prisma.user.count({ where });
        
        // Transform data for frontend
        let data = users.map((user) => this.formatManagedUser(user));

        return { data, total };
    }

    async findById(id: string, currentUser?: RequestUser) {
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

        if (currentUser && currentUser.id !== id && !isSystemAdmin(currentUser)) {
            if (!canManageOrganization(currentUser, user.organizationId, ['ORG_ADMIN'])) {
                throw new ForbiddenException('You do not have access to this user');
            }
        }

        return this.formatManagedUser(user);
    }

    async findByEmail(email: string) {
        return this.prisma.user.findUnique({
            where: { email },
            include: { roles: true },
        });
    }

    async update(id: string, data: { name?: string; isActive?: boolean }) {
        return this.prisma.user.update({
            where: { id },
            data,
        });
    }

    async createUser(data: {
        email: string;
        name: string;
        password: string;
        role?: string;
        status?: string;
        organizationId?: string;
    }, currentUser?: RequestUser) {
        if (!data.email || !data.name || !data.password) {
            throw new BadRequestException('email, name, and password are required');
        }

        const role = data.role || 'DEVELOPER';
        if (!this.validRoles.includes(role)) {
            throw new BadRequestException(`Invalid role: ${role}. Valid roles are: ${this.validRoles.join(', ')}`);
        }

        const organizationId = this.resolveOrganizationForRole(currentUser, data.organizationId, role);

        if (organizationId) {
            const organization = await this.prisma.organization.findUnique({
                where: { id: organizationId },
                select: { id: true },
            });
            if (!organization) {
                throw new BadRequestException('Organization not found');
            }
        }

        const existing = await this.prisma.user.findUnique({
            where: { email: data.email.toLowerCase() },
            select: { id: true },
        });
        if (existing) {
            throw new BadRequestException('A user with this email already exists');
        }

        const passwordHash = await bcrypt.hash(data.password, this.bcryptRounds);

        const user = await this.prisma.user.create({
            data: {
                email: data.email.toLowerCase(),
                name: data.name,
                passwordHash,
                passwordChangedAt: new Date(),
                isActive: data.status !== 'INACTIVE',
                organizationId,
                roles: {
                    create: {
                        role: role as Role,
                        scope: role === 'SYSTEM_ADMIN' ? 'SYSTEM' : 'ORGANIZATION',
                        scopeId: role === 'SYSTEM_ADMIN' ? null : organizationId,
                    },
                },
            },
            include: {
                roles: true,
                organization: { select: { id: true, name: true } },
                mfa: true,
            },
        });

        return this.formatManagedUser(user);
    }

    async updateUser(id: string, data: { name?: string; role?: string; status?: string; organizationId?: string }, currentUser?: RequestUser) {
        // Validate role if provided
        if (data.role && !this.validRoles.includes(data.role)) {
            throw new BadRequestException(`Invalid role: ${data.role}. Valid roles are: ${this.validRoles.join(', ')}`);
        }

        const target = await this.prisma.user.findUnique({
            where: { id },
            include: { roles: true },
        });

        if (!target) {
            throw new NotFoundException('User not found');
        }

        const currentIsSystemAdmin = currentUser ? isSystemAdmin(currentUser) : false;
        if (currentUser && !currentIsSystemAdmin) {
            if (!canManageOrganization(currentUser, target.organizationId, ['ORG_ADMIN'])) {
                throw new ForbiddenException('You do not have permission to update this user');
            }
            if (target.roles.some((role) => role.role === 'SYSTEM_ADMIN')) {
                throw new ForbiddenException('Only system administrators can update system administrators');
            }
            if (data.role === 'SYSTEM_ADMIN') {
                throw new ForbiddenException('Only system administrators can assign SYSTEM_ADMIN');
            }
            if (data.organizationId !== undefined && data.organizationId !== target.organizationId) {
                throw new ForbiddenException('Organization administrators cannot move users between organizations');
            }
        }
        
        // First update the user basic info
        const updateData: { name?: string; isActive?: boolean; organizationId?: string | null } = {};
        if (data.name) updateData.name = data.name;
        if (data.status) updateData.isActive = data.status === 'ACTIVE';
        const roleBecomesSystemAdmin = data.role === 'SYSTEM_ADMIN';
        if (roleBecomesSystemAdmin) {
            updateData.organizationId = null;
        } else if (data.organizationId !== undefined) {
            updateData.organizationId = data.organizationId || null;
        }

        const nextOrganizationId = roleBecomesSystemAdmin
            ? null
            : data.organizationId !== undefined
            ? data.organizationId || null
            : target.organizationId;

        if (data.role && data.role !== 'SYSTEM_ADMIN' && !nextOrganizationId) {
            throw new BadRequestException('organizationId is required for organization-scoped roles');
        }

        // Only update user if there's data to update
        if (Object.keys(updateData).length > 0) {
            await this.prisma.user.update({
                where: { id },
                data: updateData,
            });
        }

        // If role is being updated, update the user's primary role
        if (data.role) {
            // Delete existing roles and create new one
            await this.prisma.userRole.deleteMany({ where: { userId: id } });
            await this.prisma.userRole.create({
                data: {
                    userId: id,
                    role: data.role as 'SYSTEM_ADMIN' | 'ORG_ADMIN' | 'SECURITY_ADMIN' | 'PROJECT_ADMIN' | 'DEVELOPER' | 'VIEWER',
                    scope: data.role === 'SYSTEM_ADMIN' ? 'SYSTEM' : 'ORGANIZATION',
                    scopeId: data.role === 'SYSTEM_ADMIN' ? null : nextOrganizationId,
                },
            });
        } else if (data.organizationId !== undefined && nextOrganizationId) {
            await this.prisma.userRole.updateMany({
                where: { userId: id, scope: 'ORGANIZATION' },
                data: { scopeId: nextOrganizationId },
            });
        }

        // Fetch and return updated user with transformed data
        const user = await this.prisma.user.findUnique({
            where: { id },
            include: { 
                roles: true, 
                organization: { select: { id: true, name: true } },
                mfa: true,
            },
        });
        
        if (!user) throw new NotFoundException('User not found');

        return this.formatManagedUser(user);
    }

    async deleteUser(id: string, currentUser?: RequestUser) {
        const target = await this.prisma.user.findUnique({
            where: { id },
            include: { roles: true },
        });

        if (!target) {
            throw new NotFoundException('User not found');
        }

        if (currentUser?.id === id) {
            throw new BadRequestException('You cannot delete your own account');
        }

        if (currentUser && !isSystemAdmin(currentUser)) {
            if (!canManageOrganization(currentUser, target.organizationId, ['ORG_ADMIN'])) {
                throw new ForbiddenException('You do not have permission to delete this user');
            }
            if (target.roles.some((role) => role.role === 'SYSTEM_ADMIN')) {
                throw new ForbiddenException('Only system administrators can delete system administrators');
            }
        }

        // First delete related records
        await this.prisma.userRole.deleteMany({ where: { userId: id } });
        return this.prisma.user.delete({
            where: { id },
        });
    }

    async assignRole(userId: string, role: string, scope: string, scopeId?: string) {
        return this.prisma.userRole.create({
            data: {
                userId,
                role: role as any,
                scope: scope as any,
                scopeId,
            },
        });
    }

    async removeRole(userId: string, roleId: string) {
        return this.prisma.userRole.delete({
            where: { id: roleId },
        });
    }

    // In-memory storage for notification settings (in production, add to User model)
    private notificationSettings: Map<string, { emailAlerts: boolean; criticalOnly: boolean; weeklyDigest: boolean }> = new Map();

    async getNotificationSettings(userId: string): Promise<{ emailAlerts: boolean; criticalOnly: boolean; weeklyDigest: boolean }> {
        const settings = this.notificationSettings.get(userId);
        if (!settings) {
            // Return default settings
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
}

