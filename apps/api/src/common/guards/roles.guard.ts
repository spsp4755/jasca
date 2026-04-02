import { Injectable, CanActivate, ExecutionContext, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';
import { PrismaService } from '../../prisma/prisma.service';
import {
    DEFAULT_PERMISSION_MATRIX,
    hasAllPermissions,
    normalizePermissionMatrix,
    type PermissionMatrix,
    resolvePermissionsForRoles,
} from '../authorization/permissions';

// Permission to role mapping for API tokens
// Maps actual permission strings from DB to roles required by endpoints
const PERMISSION_ROLE_MAP: Record<string, string[]> = {
    // Scan permissions
    'scans:read': ['DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'VIEWER'],
    'scans:write': ['DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN'],
    'scan:upload': ['DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN'],
    'scan:read': ['DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'VIEWER'],
    // Project permissions
    'projects:read': ['DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'VIEWER'],
    'projects:write': ['PROJECT_ADMIN', 'ORG_ADMIN'],
    'project:read': ['DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'VIEWER'],
    'project:write': ['PROJECT_ADMIN', 'ORG_ADMIN'],
    // Vulnerability permissions
    'vulnerabilities:read': ['DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'VIEWER'],
    'vulnerabilities:write': ['PROJECT_ADMIN', 'ORG_ADMIN'],
    'vuln:read': ['DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'VIEWER'],
    'vuln:write': ['PROJECT_ADMIN', 'ORG_ADMIN'],
    // Report permissions
    'reports:read': ['DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'VIEWER'],
    'reports:write': ['PROJECT_ADMIN', 'ORG_ADMIN'],
    'report:read': ['DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'VIEWER'],
    'report:write': ['PROJECT_ADMIN', 'ORG_ADMIN'],
    // Policy permissions
    'policies:read': ['DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'VIEWER'],
    'policies:write': ['PROJECT_ADMIN', 'ORG_ADMIN'],
    // Admin
    'admin': ['ORG_ADMIN'],
};

const API_TOKEN_PERMISSION_ALIASES: Record<string, string[]> = {
    'scan:read': ['scan:read', 'scans:read', 'admin'],
    'scan:create': ['scan:create', 'scan:upload', 'scans:write', 'admin'],
    'scan:delete': ['scan:delete', 'scans:write', 'admin'],
    'project:read': ['project:read', 'projects:read', 'admin'],
    'project:create': ['project:create', 'project:write', 'projects:write', 'admin'],
    'project:update': ['project:update', 'project:write', 'projects:write', 'admin'],
    'project:delete': ['project:delete', 'project:write', 'projects:write', 'admin'],
    'vuln:read': ['vuln:read', 'vulnerabilities:read', 'admin'],
    'vuln:update': ['vuln:update', 'vuln:write', 'vulnerabilities:write', 'admin'],
    'vuln:assign': ['vuln:assign', 'vuln:write', 'vulnerabilities:write', 'admin'],
    'policy:read': ['policy:read', 'policies:read', 'admin'],
    'policy:create': ['policy:create', 'policy:write', 'policies:write', 'admin'],
    'policy:update': ['policy:update', 'policy:write', 'policies:write', 'admin'],
    'policy:delete': ['policy:delete', 'policy:write', 'policies:write', 'admin'],
    'exception:read': ['exception:read', 'admin'],
    'exception:request': ['exception:request', 'admin'],
    'exception:approve': ['exception:approve', 'admin'],
    'user:read': ['user:read', 'admin'],
    'user:create': ['user:create', 'admin'],
    'user:update': ['user:update', 'admin'],
    'user:delete': ['user:delete', 'admin'],
    'org:read': ['org:read', 'admin'],
    'org:create': ['org:create', 'admin'],
    'org:update': ['org:update', 'admin'],
    'org:delete': ['org:delete', 'admin'],
    'settings:read': ['settings:read', 'admin'],
    'settings:update': ['settings:update', 'admin'],
};

@Injectable()
export class RolesGuard implements CanActivate {
    private readonly logger = new Logger(RolesGuard.name);

    constructor(
        private reflector: Reflector,
        private prisma: PrismaService,
    ) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        const requiredPermissions = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (!requiredRoles && !requiredPermissions) {
            return true;
        }

        const { user } = context.switchToHttp().getRequest();

        if (!user) {
            return false;
        }

        // Handle API token authentication
        if (user.isApiToken && user.permissions) {
            if (requiredPermissions && !this.hasApiTokenPermissions(user.permissions, requiredPermissions)) {
                return false;
            }

            if (!requiredRoles) {
                return true;
            }

            return this.hasRequiredRolesFromApiToken(user.permissions, requiredRoles);
        }

        if (!user.roles) {
            return false;
        }

        const userRoles = user.roles.map((r: any) => r.role || r);

        // Admin hierarchy
        if (userRoles.includes('SYSTEM_ADMIN')) {
            return true;
        }

        if (requiredPermissions) {
            const permissionMatrix = await this.getPermissionMatrix();
            const grantedPermissions = resolvePermissionsForRoles(userRoles, permissionMatrix);
            if (!hasAllPermissions(grantedPermissions, requiredPermissions)) {
                return false;
            }
        }

        if (!requiredRoles) {
            return true;
        }

        if (requiredRoles.includes('ORG_ADMIN') && userRoles.includes('ORG_ADMIN')) {
            return true;
        }

        return requiredRoles.some((role) => userRoles.includes(role));
    }

    private async getPermissionMatrix(): Promise<PermissionMatrix> {
        try {
            const permissionSetting = await this.prisma.systemSettings.findUnique({
                where: { key: 'permissions' },
                select: { value: true },
            });

            return normalizePermissionMatrix(permissionSetting?.value);
        } catch (error) {
            const message = error instanceof Error ? error.message : 'unknown error';
            this.logger.warn(`Falling back to default permission matrix: ${message}`);
            return DEFAULT_PERMISSION_MATRIX;
        }
    }

    private hasApiTokenPermissions(grantedPermissions: string[], requiredPermissions: string[]): boolean {
        return requiredPermissions.every((permission) => {
            const aliases = API_TOKEN_PERMISSION_ALIASES[permission] || [permission];
            return aliases.some((alias) => grantedPermissions.includes(alias));
        });
    }

    private hasRequiredRolesFromApiToken(grantedPermissions: string[], requiredRoles: string[]): boolean {
        for (const permission of grantedPermissions) {
            const grantedRoles = PERMISSION_ROLE_MAP[permission] || [];
            if (requiredRoles.some((role) => grantedRoles.includes(role))) {
                return true;
            }
        }

        return grantedPermissions.includes('admin');
    }
}
