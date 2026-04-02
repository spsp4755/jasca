const DEFAULT_ROLE_PERMISSIONS: Record<string, string[]> = {
    SYSTEM_ADMIN: [
        'scan:read', 'scan:create', 'scan:delete',
        'vuln:read', 'vuln:update', 'vuln:assign',
        'project:read', 'project:create', 'project:update', 'project:delete',
        'policy:read', 'policy:create', 'policy:update', 'policy:delete',
        'exception:read', 'exception:request', 'exception:approve',
        'user:read', 'user:create', 'user:update', 'user:delete',
        'org:read', 'org:create', 'org:update', 'org:delete',
        'settings:read', 'settings:update',
    ],
    ORG_ADMIN: [
        'scan:read', 'scan:create', 'scan:delete',
        'vuln:read', 'vuln:update', 'vuln:assign',
        'project:read', 'project:create', 'project:update', 'project:delete',
        'policy:read', 'policy:create', 'policy:update', 'policy:delete',
        'exception:read', 'exception:request', 'exception:approve',
        'user:read', 'user:create', 'user:update', 'user:delete',
        'org:read', 'org:update',
        'settings:read', 'settings:update',
    ],
    SECURITY_ADMIN: [
        'scan:read', 'scan:create', 'scan:delete',
        'vuln:read', 'vuln:update', 'vuln:assign',
        'project:read',
        'policy:read', 'policy:create', 'policy:update',
        'exception:read', 'exception:request', 'exception:approve',
        'user:read',
        'org:read',
        'settings:read',
    ],
    PROJECT_ADMIN: [
        'scan:read', 'scan:create', 'scan:delete',
        'vuln:read', 'vuln:update', 'vuln:assign',
        'project:read', 'project:update',
        'policy:read', 'policy:create', 'policy:update',
        'exception:read', 'exception:request', 'exception:approve',
        'user:read',
        'org:read',
    ],
    DEVELOPER: [
        'scan:read', 'scan:create',
        'vuln:read', 'vuln:update',
        'project:read',
        'policy:read',
        'exception:read', 'exception:request',
        'org:read',
    ],
    VIEWER: [
        'scan:read',
        'vuln:read',
        'project:read',
        'policy:read',
        'exception:read',
        'org:read',
    ],
};

export type PermissionUser = {
    roles?: Array<string | { role?: string }>;
    permissions?: string[];
};

export function getRoleNames(user?: PermissionUser | null): string[] {
    return (user?.roles || []).map((role) => (typeof role === 'string' ? role : role.role || '')).filter(Boolean);
}

export function getUserPermissions(user?: PermissionUser | null): string[] {
    if (!user) {
        return [];
    }

    if (user.permissions?.length) {
        return user.permissions;
    }

    const permissions = new Set<string>();
    for (const role of getRoleNames(user)) {
        for (const permission of DEFAULT_ROLE_PERMISSIONS[role] || []) {
            permissions.add(permission);
        }
    }

    return Array.from(permissions);
}

export function hasPermission(user: PermissionUser | null | undefined, permission: string): boolean {
    return getUserPermissions(user).includes(permission);
}

export function hasAnyPermission(
    user: PermissionUser | null | undefined,
    permissions: string[],
): boolean {
    const granted = new Set(getUserPermissions(user));
    return permissions.some((permission) => granted.has(permission));
}

export function isAdminUser(user: PermissionUser | null | undefined): boolean {
    return hasAnyPermission(user, [
        'user:read',
        'project:update',
        'policy:update',
        'settings:read',
        'settings:update',
        'org:update',
    ]);
}
