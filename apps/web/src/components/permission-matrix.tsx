'use client';

import * as React from 'react';
import { Check, X, Info, Shield, User, Eye, Settings, FileText, AlertTriangle } from 'lucide-react';
import { Tooltip } from '@/components/ui/tooltip';

// ============================================
// Types
// ============================================
export type Permission = 'view' | 'create' | 'edit' | 'delete' | 'approve' | 'admin';
export type Role = 'SYSTEM_ADMIN' | 'ORG_ADMIN' | 'SECURITY_ADMIN' | 'PROJECT_ADMIN' | 'DEVELOPER' | 'VIEWER';

export interface PermissionMatrixData {
    resource: string;
    resourceLabel: string;
    permissions: Record<Role, Permission[]>;
}

// ============================================
// Default Permission Matrix
// ============================================
const defaultPermissions: PermissionMatrixData[] = [
    {
        resource: 'vulnerabilities',
        resourceLabel: '취약점',
        permissions: {
            SYSTEM_ADMIN: ['view', 'create', 'edit', 'delete', 'approve', 'admin'],
            ORG_ADMIN: ['view', 'create', 'edit', 'delete', 'approve'],
            SECURITY_ADMIN: ['view', 'create', 'edit', 'delete', 'approve'],
            PROJECT_ADMIN: ['view', 'edit', 'approve'],
            DEVELOPER: ['view', 'edit'],
            VIEWER: ['view'],
        },
    },
    {
        resource: 'policies',
        resourceLabel: '정책',
        permissions: {
            SYSTEM_ADMIN: ['view', 'create', 'edit', 'delete', 'approve', 'admin'],
            ORG_ADMIN: ['view', 'create', 'edit', 'delete', 'approve'],
            SECURITY_ADMIN: ['view', 'create', 'edit', 'delete'],
            PROJECT_ADMIN: ['view'],
            DEVELOPER: ['view'],
            VIEWER: ['view'],
        },
    },
    {
        resource: 'exceptions',
        resourceLabel: '예외',
        permissions: {
            SYSTEM_ADMIN: ['view', 'create', 'edit', 'delete', 'approve', 'admin'],
            ORG_ADMIN: ['view', 'create', 'edit', 'delete', 'approve'],
            SECURITY_ADMIN: ['view', 'create', 'edit', 'approve'],
            PROJECT_ADMIN: ['view', 'create', 'approve'],
            DEVELOPER: ['view', 'create'],
            VIEWER: ['view'],
        },
    },
    {
        resource: 'projects',
        resourceLabel: '프로젝트',
        permissions: {
            SYSTEM_ADMIN: ['view', 'create', 'edit', 'delete', 'admin'],
            ORG_ADMIN: ['view', 'create', 'edit', 'delete'],
            SECURITY_ADMIN: ['view', 'edit'],
            PROJECT_ADMIN: ['view', 'edit'],
            DEVELOPER: ['view'],
            VIEWER: ['view'],
        },
    },
    {
        resource: 'users',
        resourceLabel: '사용자',
        permissions: {
            SYSTEM_ADMIN: ['view', 'create', 'edit', 'delete', 'admin'],
            ORG_ADMIN: ['view', 'create', 'edit', 'delete'],
            SECURITY_ADMIN: ['view'],
            PROJECT_ADMIN: [],
            DEVELOPER: [],
            VIEWER: [],
        },
    },
    {
        resource: 'reports',
        resourceLabel: '리포트',
        permissions: {
            SYSTEM_ADMIN: ['view', 'create', 'edit', 'delete'],
            ORG_ADMIN: ['view', 'create', 'edit', 'delete'],
            SECURITY_ADMIN: ['view', 'create', 'edit'],
            PROJECT_ADMIN: ['view', 'create'],
            DEVELOPER: ['view'],
            VIEWER: ['view'],
        },
    },
];

const roles: { key: Role; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { key: 'SYSTEM_ADMIN', label: 'System Admin', icon: Shield },
    { key: 'ORG_ADMIN', label: 'Org Admin', icon: Settings },
    { key: 'SECURITY_ADMIN', label: 'Security Admin', icon: AlertTriangle },
    { key: 'PROJECT_ADMIN', label: 'Project Admin', icon: FileText },
    { key: 'DEVELOPER', label: 'Developer', icon: User },
    { key: 'VIEWER', label: 'Viewer', icon: Eye },
];

const permissionLabels: Record<Permission, string> = {
    view: '조회',
    create: '생성',
    edit: '수정',
    delete: '삭제',
    approve: '승인',
    admin: '관리',
};

// ============================================
// Permission Matrix Component
// ============================================
export interface PermissionMatrixProps {
    data?: PermissionMatrixData[];
    editable?: boolean;
    onPermissionChange?: (resource: string, role: Role, permissions: Permission[]) => void;
}

export function PermissionMatrix({
    data = defaultPermissions,
    editable = false,
    onPermissionChange,
}: PermissionMatrixProps) {
    return (
        <div className="overflow-x-auto">
            <table className="w-full border-collapse">
                <thead>
                    <tr className="bg-slate-50 dark:bg-slate-800">
                        <th className="text-left px-4 py-3 font-medium text-slate-600 dark:text-slate-400 text-sm border-b border-slate-200 dark:border-slate-700">
                            리소스
                        </th>
                        {roles.map((role) => {
                            const Icon = role.icon;
                            return (
                                <th
                                    key={role.key}
                                    className="text-center px-2 py-3 font-medium text-slate-600 dark:text-slate-400 text-xs border-b border-slate-200 dark:border-slate-700 min-w-[100px]"
                                >
                                    <Tooltip content={role.label}>
                                        <div className="flex flex-col items-center gap-1">
                                            <Icon className="h-4 w-4" />
                                            <span className="truncate max-w-[80px]">{role.label.split(' ')[0]}</span>
                                        </div>
                                    </Tooltip>
                                </th>
                            );
                        })}
                    </tr>
                </thead>
                <tbody>
                    {data.map((resource, rowIndex) => (
                        <tr
                            key={resource.resource}
                            className={rowIndex % 2 === 0 ? 'bg-white dark:bg-slate-900' : 'bg-slate-50/50 dark:bg-slate-800/50'}
                        >
                            <td className="px-4 py-3 font-medium text-slate-900 dark:text-white text-sm border-b border-slate-100 dark:border-slate-800">
                                {resource.resourceLabel}
                            </td>
                            {roles.map((role) => {
                                const perms = resource.permissions[role.key] || [];
                                return (
                                    <td
                                        key={role.key}
                                        className="text-center px-2 py-3 border-b border-slate-100 dark:border-slate-800"
                                    >
                                        <PermissionCell
                                            permissions={perms}
                                            editable={editable}
                                            onChange={(newPerms) => onPermissionChange?.(resource.resource, role.key, newPerms)}
                                        />
                                    </td>
                                );
                            })}
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

// ============================================
// Permission Cell
// ============================================
interface PermissionCellProps {
    permissions: Permission[];
    editable?: boolean;
    onChange?: (permissions: Permission[]) => void;
}

function PermissionCell({ permissions, editable = false, onChange }: PermissionCellProps) {
    if (permissions.length === 0) {
        return (
            <div className="flex justify-center">
                <X className="h-4 w-4 text-slate-300 dark:text-slate-600" />
            </div>
        );
    }

    const permissionString = permissions.map((p) => permissionLabels[p]).join(', ');

    return (
        <Tooltip content={permissionString}>
            <div className="flex justify-center gap-0.5 flex-wrap">
                {permissions.map((perm) => (
                    <span
                        key={perm}
                        className={`inline-flex items-center justify-center w-5 h-5 rounded text-[10px] font-medium ${getPermissionColor(perm)}`}
                        title={permissionLabels[perm]}
                    >
                        {perm[0].toUpperCase()}
                    </span>
                ))}
            </div>
        </Tooltip>
    );
}

function getPermissionColor(permission: Permission): string {
    const colors: Record<Permission, string> = {
        view: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
        create: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
        edit: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
        delete: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
        approve: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
        admin: 'bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-300',
    };
    return colors[permission];
}

// ============================================
// Role Badge
// ============================================
export interface RoleBadgeProps {
    role: Role;
    size?: 'sm' | 'md';
}

export function RoleBadge({ role, size = 'md' }: RoleBadgeProps) {
    const roleInfo = roles.find((r) => r.key === role);
    if (!roleInfo) return null;

    const Icon = roleInfo.icon;
    const sizeClasses = size === 'sm' ? 'text-xs px-2 py-0.5' : 'text-sm px-2.5 py-1';

    const colorClasses: Record<Role, string> = {
        SYSTEM_ADMIN: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
        ORG_ADMIN: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
        SECURITY_ADMIN: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
        PROJECT_ADMIN: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-300',
        DEVELOPER: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
        VIEWER: 'bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-300',
    };

    return (
        <span className={`inline-flex items-center gap-1.5 rounded-full font-medium ${sizeClasses} ${colorClasses[role]}`}>
            <Icon className={size === 'sm' ? 'h-3 w-3' : 'h-4 w-4'} />
            {roleInfo.label}
        </span>
    );
}
