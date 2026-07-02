'use client';

import { useState, useEffect, useMemo } from 'react';
import Link from 'next/link';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import {
    Shield,
    LayoutDashboard,
    FileSearch,
    AlertTriangle,
    FileText,
    Settings,
    ChevronLeft,
    ChevronRight,
    LogOut,
    User,
    Loader2,
    FolderKanban,
    Bell,
    Map,
    Database,
    Key,
    Scale,
    Book,
    Menu,
    X,
} from 'lucide-react';
import { useAuthStore } from '@/stores/auth-store';
import { authApi } from '@/lib/auth-api';
import { useHasMounted } from '@/hooks/use-has-mounted';
import { Breadcrumb } from '@/components/breadcrumb';
import { RecentProjects } from '@/components/recent-projects';
import { ToastProvider } from '@/components/ui/toast';
import { NotificationCenter } from '@/components/notification-center';
import { useMarkNotificationRead, useNotifications } from '@/lib/api-hooks';

// Role types for navigation
type NavRole = 'SYSTEM_ADMIN' | 'ORG_ADMIN' | 'SECURITY_ADMIN' | 'PROJECT_ADMIN' | 'DEVELOPER' | 'VIEWER';

interface NavItem {
    name: string;
    href: string;
    icon: any;
    roles: NavRole[] | 'all';
}

// Role-based navigation configuration
const allNavigation: NavItem[] = [
    { name: '대시보드', href: '/dashboard', icon: LayoutDashboard, roles: 'all' },
    { name: '프로젝트', href: '/dashboard/projects', icon: FolderKanban, roles: 'all' },
    { name: '스캔 결과', href: '/dashboard/scans', icon: FileSearch, roles: 'all' },
    { name: '취약점', href: '/dashboard/vulnerabilities', icon: AlertTriangle, roles: 'all' },
    { name: '라이선스', href: '/dashboard/licenses', icon: Scale, roles: 'all' },
    { name: 'Trivy DB', href: '/dashboard/trivy-db', icon: Database, roles: ['SYSTEM_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN'] },
    { name: '정책', href: '/dashboard/policies', icon: FileText, roles: ['SYSTEM_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN'] },

    { name: 'API 토큰', href: '/dashboard/api-tokens', icon: Key, roles: 'all' },
    { name: '연동 가이드', href: '/dashboard/guide', icon: Book, roles: 'all' },
    { name: '알림', href: '/dashboard/notifications', icon: Bell, roles: 'all' },
    { name: '설정', href: '/dashboard/settings', icon: Settings, roles: 'all' },
    { name: '사이트맵', href: '/dashboard/sitemap', icon: Map, roles: 'all' },
];

function getNavigationForRole(userRoles: string[]) {
    return allNavigation.filter((item) => {
        if (item.roles === 'all') return true;
        return item.roles.some((role) => userRoles.includes(role));
    });
}

export default function DashboardLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    const pathname = usePathname();
    const router = useRouter();
    const searchParams = useSearchParams();
    const [collapsed, setCollapsed] = useState(false);
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
    const { user, isAuthenticated, refreshToken, logout, setTokens, setUser } = useAuthStore();
    const hasMounted = useHasMounted();
    const { data: notifications = [] } = useNotifications();
    const { mutate: markNotificationRead } = useMarkNotificationRead();

    // Get user roles from user object
    const userRoles = useMemo(() => {
        if (!user) return [];
        // Assume roles are stored in user.roles array
        return (user as any).roles?.map((r: any) => r.role || r) || ['VIEWER'];
    }, [user]);

    // Filter navigation based on user role
    const navigation = useMemo(() => getNavigationForRole(userRoles), [userRoles]);

    // Handle SSO callback tokens from URL
    useEffect(() => {
        const accessToken = searchParams.get('accessToken');
        const refreshTokenParam = searchParams.get('refreshToken');

        if (accessToken && refreshTokenParam) {
            // Store tokens from SSO callback
            setTokens(accessToken, refreshTokenParam);

            // Decode JWT to get user info
            try {
                const payload = JSON.parse(atob(accessToken.split('.')[1]));
                setUser({
                    id: payload.sub,
                    email: payload.email,
                    name: payload.email?.split('@')[0] || 'User',
                    organizationId: payload.organizationId,
                    roles: payload.roles || [],
                });
            } catch (e) {
                console.error('Failed to decode JWT:', e);
            }

            // Clean URL by removing token params
            const url = new URL(window.location.href);
            url.searchParams.delete('accessToken');
            url.searchParams.delete('refreshToken');
            window.history.replaceState({}, '', url.pathname);
        }
    }, [searchParams, setTokens, setUser]);

    // Auth guard - redirect if not authenticated (after hydration)
    useEffect(() => {
        if (hasMounted && !isAuthenticated) {
            router.push('/login');
        }
    }, [isAuthenticated, router, hasMounted]);

    useEffect(() => {
        if (!pathname || notifications.length === 0) return;

        const matchingUnread = notifications.filter((notification) => (
            !notification.isRead && notification.link === pathname
        ));

        matchingUnread.forEach((notification) => {
            markNotificationRead(notification.id);
        });
    }, [pathname, notifications, markNotificationRead]);

    const handleLogout = async () => {
        try {
            if (refreshToken) {
                await authApi.logout(refreshToken);
            }
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            logout();
            router.push('/login');
        }
    };

    // Show loading while hydrating
    if (!hasMounted) {
        return (
            <div className="flex h-screen items-center justify-center bg-slate-50 dark:bg-slate-900">
                <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
            </div>
        );
    }

    // Don't render if not authenticated
    if (!isAuthenticated) {
        return null;
    }

    const renderNavigation = (isCollapsed: boolean, onNavigate?: () => void) => (
        <nav className="flex-1 p-4 space-y-1 overflow-y-auto custom-scrollbar">
            {navigation.map((item) => {
                const isActive = pathname === item.href || pathname?.startsWith(item.href + '/');
                return (
                    <Link
                        key={item.name}
                        href={item.href}
                        onClick={onNavigate}
                        className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${isActive
                            ? 'bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400'
                            : 'text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-700/50'
                            }`}
                        title={isCollapsed ? item.name : undefined}
                    >
                        <item.icon className="h-5 w-5 flex-shrink-0" />
                        {!isCollapsed && <span>{item.name}</span>}
                    </Link>
                );
            })}
        </nav>
    );

    return (
        <ToastProvider>
            <div className="flex h-screen bg-slate-50 dark:bg-slate-900">
                {/* Sidebar */}
                <aside
                    className={`${collapsed ? 'w-20' : 'w-64'
                        } hidden md:flex flex-shrink-0 bg-white dark:bg-slate-800 border-r border-slate-200 dark:border-slate-700 transition-all duration-300 flex-col`}
                >
                    {/* Logo */}
                    <div className="flex items-center gap-3 px-6 py-5 border-b border-slate-200 dark:border-slate-700">
                        <Shield className="h-8 w-8 text-blue-600 flex-shrink-0" />
                        {!collapsed && (
                            <span className="text-xl font-bold text-slate-900 dark:text-white">
                                JASCA
                            </span>
                        )}
                    </div>

                    {/* Navigation */}
                    {renderNavigation(collapsed)}

                    {/* Recent Projects Section */}
                    {!collapsed && (
                        <div className="border-t border-slate-200 dark:border-slate-700 py-2">
                            <RecentProjects collapsed={collapsed} />
                        </div>
                    )}

                    {/* Collapse button */}
                    <div className="p-4 border-t border-slate-200 dark:border-slate-700">
                        <button
                            onClick={() => setCollapsed(!collapsed)}
                            className="flex items-center justify-center w-full p-2 rounded-lg text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-700/50 transition-colors"
                            aria-label={collapsed ? '사이드바 펼치기' : '사이드바 접기'}
                        >
                            {collapsed ? (
                                <ChevronRight className="h-5 w-5" />
                            ) : (
                                <>
                                    <ChevronLeft className="h-5 w-5" />
                                    <span className="ml-2">접기</span>
                                </>
                            )}
                        </button>
                    </div>
                </aside>

                {mobileMenuOpen && (
                    <div className="fixed inset-0 z-50 md:hidden">
                        <button
                            type="button"
                            aria-label="모바일 메뉴 닫기"
                            className="absolute inset-0 bg-slate-900/40"
                            onClick={() => setMobileMenuOpen(false)}
                        />
                        <aside className="relative flex h-full w-72 max-w-[85vw] flex-col bg-white shadow-xl dark:bg-slate-800">
                            <div className="flex items-center justify-between gap-3 px-5 py-4 border-b border-slate-200 dark:border-slate-700">
                                <div className="flex items-center gap-3">
                                    <Shield className="h-7 w-7 text-blue-600 flex-shrink-0" />
                                    <span className="text-lg font-bold text-slate-900 dark:text-white">JASCA</span>
                                </div>
                                <button
                                    type="button"
                                    onClick={() => setMobileMenuOpen(false)}
                                    className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-700"
                                    aria-label="모바일 메뉴 닫기"
                                >
                                    <X className="h-5 w-5" />
                                </button>
                            </div>
                            {renderNavigation(false, () => setMobileMenuOpen(false))}
                        </aside>
                    </div>
                )}

                {/* Main content */}
                <div className="min-w-0 flex-1 flex flex-col overflow-hidden">
                    {/* Header */}
                    <header className="h-16 bg-white dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between gap-3 px-4 sm:px-6">
                        <div className="flex min-w-0 items-center gap-3">
                            <button
                                type="button"
                                onClick={() => setMobileMenuOpen(true)}
                                className="rounded-lg p-2 text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-700 md:hidden"
                                aria-label="모바일 메뉴 열기"
                            >
                                <Menu className="h-5 w-5" />
                            </button>
                            <div className="min-w-0 flex flex-col">
                                <h1 className="truncate text-lg font-semibold text-slate-900 dark:text-white">
                                    {navigation.find((n) => pathname?.startsWith(n.href))?.name || '대시보드'}
                                </h1>
                                <Breadcrumb className="mt-0.5" />
                            </div>
                        </div>
                        <div className="flex flex-shrink-0 items-center gap-2 sm:gap-4">
                            <NotificationCenter />
                            {/* User info */}
                            {user && (
                                <Link
                                    href="/dashboard/profile"
                                    className="flex items-center gap-2 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors"
                                >
                                    <div className="h-8 w-8 rounded-full bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center">
                                        <User className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                                    </div>
                                    <span className="hidden text-sm font-medium sm:inline">{user.name || user.email}</span>
                                </Link>
                            )}
                            {/* Admin link - only for admin users */}
                            {(userRoles.includes('SYSTEM_ADMIN') || userRoles.includes('ORG_ADMIN')) && (
                                <Link
                                    href="/admin"
                                    className="flex items-center gap-2 px-3 py-2 text-sm text-purple-600 hover:text-purple-700 dark:text-purple-400 dark:hover:text-purple-300 transition-colors rounded-lg hover:bg-purple-50 dark:hover:bg-purple-900/20 border border-purple-200 dark:border-purple-800"
                                >
                                    <Settings className="h-4 w-4" />
                                    <span className="hidden sm:inline">관리자</span>
                                </Link>
                            )}
                            {/* Logout button */}
                            <button
                                onClick={handleLogout}
                                className="flex items-center gap-2 px-3 py-2 text-sm text-slate-600 hover:text-red-600 dark:text-slate-300 dark:hover:text-red-400 transition-colors rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700"
                            >
                                <LogOut className="h-4 w-4" />
                                <span className="hidden sm:inline">로그아웃</span>
                            </button>
                        </div>
                    </header>

                    {/* Content */}
                    <main className="flex-1 overflow-auto p-6 custom-scrollbar">{children}</main>
                </div>
            </div>
        </ToastProvider>
    );
}
