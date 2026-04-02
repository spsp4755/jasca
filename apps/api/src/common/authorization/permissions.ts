export const APP_ROLES = [
    'SYSTEM_ADMIN',
    'ORG_ADMIN',
    'SECURITY_ADMIN',
    'PROJECT_ADMIN',
    'DEVELOPER',
    'VIEWER',
] as const;

export type AppRole = (typeof APP_ROLES)[number];

export interface PermissionDefinition {
    id: string;
    label: string;
}

export interface PermissionGroup {
    name: string;
    permissions: PermissionDefinition[];
}

export type PermissionMatrix = Record<AppRole, string[]>;

export const PERMISSION_GROUPS: PermissionGroup[] = [
    {
        name: 'Scans',
        permissions: [
            { id: 'scan:read', label: 'View scans' },
            { id: 'scan:create', label: 'Upload scans' },
            { id: 'scan:delete', label: 'Delete scans' },
        ],
    },
    {
        name: 'Vulnerabilities',
        permissions: [
            { id: 'vuln:read', label: 'View vulnerabilities' },
            { id: 'vuln:update', label: 'Update vulnerability status' },
            { id: 'vuln:assign', label: 'Assign vulnerabilities' },
        ],
    },
    {
        name: 'Projects',
        permissions: [
            { id: 'project:read', label: 'View projects' },
            { id: 'project:create', label: 'Create projects' },
            { id: 'project:update', label: 'Update projects' },
            { id: 'project:delete', label: 'Delete projects' },
        ],
    },
    {
        name: 'Policies',
        permissions: [
            { id: 'policy:read', label: 'View policies' },
            { id: 'policy:create', label: 'Create policies' },
            { id: 'policy:update', label: 'Update policies' },
            { id: 'policy:delete', label: 'Delete policies' },
        ],
    },
    {
        name: 'Exceptions',
        permissions: [
            { id: 'exception:read', label: 'View exceptions' },
            { id: 'exception:request', label: 'Request exceptions' },
            { id: 'exception:approve', label: 'Approve exceptions' },
        ],
    },
    {
        name: 'Users',
        permissions: [
            { id: 'user:read', label: 'View users' },
            { id: 'user:create', label: 'Create users' },
            { id: 'user:update', label: 'Update users' },
            { id: 'user:delete', label: 'Delete users' },
        ],
    },
    {
        name: 'Organizations',
        permissions: [
            { id: 'org:read', label: 'View organizations' },
            { id: 'org:create', label: 'Create organizations' },
            { id: 'org:update', label: 'Update organizations' },
            { id: 'org:delete', label: 'Delete organizations' },
        ],
    },
    {
        name: 'Settings',
        permissions: [
            { id: 'settings:read', label: 'View settings' },
            { id: 'settings:update', label: 'Update settings' },
        ],
    },
];

const ALL_PERMISSIONS = PERMISSION_GROUPS.flatMap((group) =>
    group.permissions.map((permission) => permission.id),
);

export const DEFAULT_PERMISSION_MATRIX: PermissionMatrix = {
    SYSTEM_ADMIN: [...ALL_PERMISSIONS],
    ORG_ADMIN: [
        'scan:read',
        'scan:create',
        'scan:delete',
        'vuln:read',
        'vuln:update',
        'vuln:assign',
        'project:read',
        'project:create',
        'project:update',
        'project:delete',
        'policy:read',
        'policy:create',
        'policy:update',
        'policy:delete',
        'exception:read',
        'exception:request',
        'exception:approve',
        'user:read',
        'user:create',
        'user:update',
        'user:delete',
        'org:read',
        'org:update',
        'settings:read',
        'settings:update',
    ],
    SECURITY_ADMIN: [
        'scan:read',
        'scan:create',
        'scan:delete',
        'vuln:read',
        'vuln:update',
        'vuln:assign',
        'project:read',
        'policy:read',
        'policy:create',
        'policy:update',
        'exception:read',
        'exception:request',
        'exception:approve',
        'user:read',
        'org:read',
        'settings:read',
    ],
    PROJECT_ADMIN: [
        'scan:read',
        'scan:create',
        'scan:delete',
        'vuln:read',
        'vuln:update',
        'vuln:assign',
        'project:read',
        'project:update',
        'policy:read',
        'policy:create',
        'policy:update',
        'exception:read',
        'exception:request',
        'exception:approve',
        'user:read',
        'org:read',
    ],
    DEVELOPER: [
        'scan:read',
        'scan:create',
        'vuln:read',
        'vuln:update',
        'project:read',
        'policy:read',
        'exception:read',
        'exception:request',
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

export function clonePermissionMatrix(matrix: PermissionMatrix = DEFAULT_PERMISSION_MATRIX): PermissionMatrix {
    return APP_ROLES.reduce((acc, role) => {
        acc[role] = [...(matrix[role] || [])];
        return acc;
    }, {} as PermissionMatrix);
}

export function normalizePermissionMatrix(value: unknown): PermissionMatrix {
    const baseMatrix = clonePermissionMatrix();

    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return baseMatrix;
    }

    for (const role of APP_ROLES) {
        const permissions = (value as Record<string, unknown>)[role];
        if (Array.isArray(permissions)) {
            baseMatrix[role] = Array.from(
                new Set(
                    permissions
                        .filter((permission): permission is string => typeof permission === 'string')
                        .filter((permission) => ALL_PERMISSIONS.includes(permission)),
                ),
            );
        }
    }

    return baseMatrix;
}

export function resolvePermissionsForRoles(
    roles: Array<string | null | undefined>,
    matrix: PermissionMatrix,
): string[] {
    const resolved = new Set<string>();

    for (const role of roles) {
        if (!role || !APP_ROLES.includes(role as AppRole)) {
            continue;
        }

        for (const permission of matrix[role as AppRole] || []) {
            resolved.add(permission);
        }
    }

    return Array.from(resolved);
}

export function hasAllPermissions(
    grantedPermissions: Array<string | null | undefined>,
    requiredPermissions: string[],
): boolean {
    const granted = new Set(grantedPermissions.filter((permission): permission is string => Boolean(permission)));
    return requiredPermissions.every((permission) => granted.has(permission));
}

export function getAllPermissions(): string[] {
    return [...ALL_PERMISSIONS];
}

