import { ForbiddenException } from '@nestjs/common';

export interface RequestUserRole {
    role: string;
    scope?: string | null;
    scopeId?: string | null;
}

export interface RequestUser {
    id: string;
    organizationId?: string | null;
    roles?: RequestUserRole[];
    isApiToken?: boolean;
    permissions?: string[];
}

export interface ProjectScope {
    id: string;
    organizationId: string;
}

const SYSTEM_ADMIN = 'SYSTEM_ADMIN';

export function getUserRoles(user?: RequestUser | null): RequestUserRole[] {
    return Array.isArray(user?.roles) ? user.roles : [];
}

export function isSystemAdmin(user?: RequestUser | null): boolean {
    return getUserRoles(user).some((role) => role.role === SYSTEM_ADMIN);
}

export function hasAnyRole(user: RequestUser | null | undefined, roles: string[]): boolean {
    if (!user) return false;
    if (isSystemAdmin(user)) return true;
    return getUserRoles(user).some((role) => roles.includes(role.role));
}

export function canAccessOrganization(user: RequestUser | null | undefined, organizationId?: string | null): boolean {
    if (!user || !organizationId) return false;
    if (isSystemAdmin(user)) return true;

    if (user.isApiToken) {
        return user.organizationId === organizationId;
    }

    if (user.organizationId === organizationId) return true;

    return getUserRoles(user).some((role) =>
        role.scope === 'ORGANIZATION' && role.scopeId === organizationId,
    );
}

export function canManageOrganization(
    user: RequestUser | null | undefined,
    organizationId?: string | null,
    roles: string[] = ['ORG_ADMIN'],
): boolean {
    if (!user || !organizationId) return false;
    if (isSystemAdmin(user)) return true;
    if (user.isApiToken) return false;

    return getUserRoles(user).some((role) => {
        if (!roles.includes(role.role)) return false;
        if (role.scope === 'GLOBAL' || role.scope === 'SYSTEM') return false;
        if (role.scope === 'ORGANIZATION') {
            return role.scopeId === organizationId || (!role.scopeId && user.organizationId === organizationId);
        }
        return false;
    });
}

export function canAccessProject(user: RequestUser | null | undefined, project?: ProjectScope | null): boolean {
    if (!user || !project) return false;
    if (isSystemAdmin(user)) return true;

    if (user.isApiToken) {
        return user.organizationId === project.organizationId;
    }

    if (canAccessOrganization(user, project.organizationId)) return true;

    return getUserRoles(user).some((role) =>
        role.scope === 'PROJECT' && role.scopeId === project.id,
    );
}

export function canManageProject(
    user: RequestUser | null | undefined,
    project?: ProjectScope | null,
    roles: string[] = ['ORG_ADMIN', 'PROJECT_ADMIN'],
): boolean {
    if (!user || !project) return false;
    if (isSystemAdmin(user)) return true;
    if (user.isApiToken) return false;

    return getUserRoles(user).some((role) => {
        if (!roles.includes(role.role)) return false;

        if (role.scope === 'PROJECT') {
            return role.scopeId === project.id;
        }

        if (role.scope === 'ORGANIZATION') {
            return role.scopeId === project.organizationId || (!role.scopeId && user.organizationId === project.organizationId);
        }

        return false;
    });
}

export function getScopedOrganizationIds(user: RequestUser | null | undefined): string[] | undefined {
    if (!user) return [];
    if (isSystemAdmin(user)) return undefined;

    const organizationIds = new Set<string>();
    if (user.organizationId) organizationIds.add(user.organizationId);

    for (const role of getUserRoles(user)) {
        if (role.scope === 'ORGANIZATION' && role.scopeId) {
            organizationIds.add(role.scopeId);
        }
    }

    return Array.from(organizationIds);
}

export function assertOrganizationAccess(user: RequestUser | null | undefined, organizationId?: string | null): void {
    if (!canAccessOrganization(user, organizationId)) {
        throw new ForbiddenException('You do not have access to this organization');
    }
}

export function assertOrganizationManager(
    user: RequestUser | null | undefined,
    organizationId?: string | null,
    roles: string[] = ['ORG_ADMIN'],
): void {
    if (!canManageOrganization(user, organizationId, roles)) {
        throw new ForbiddenException('You do not have permission to manage this organization');
    }
}

export function assertProjectAccess(user: RequestUser | null | undefined, project?: ProjectScope | null): void {
    if (!canAccessProject(user, project)) {
        throw new ForbiddenException('You do not have access to this project');
    }
}

export function assertProjectManager(
    user: RequestUser | null | undefined,
    project?: ProjectScope | null,
    roles: string[] = ['ORG_ADMIN', 'PROJECT_ADMIN'],
): void {
    if (!canManageProject(user, project, roles)) {
        throw new ForbiddenException('You do not have permission to manage this project');
    }
}
