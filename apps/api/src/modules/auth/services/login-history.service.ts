import { Injectable, Logger } from '@nestjs/common';
import { LoginStatus } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';

export interface LoginAttemptInfo {
    userId: string;
    status: LoginStatus;
    ipAddress?: string;
    userAgent?: string;
    deviceId?: string;
    failReason?: string;
}

export interface LoginHistoryEntry {
    id: string;
    status: LoginStatus;
    ipAddress: string | null;
    userAgent: string | null;
    location: any;
    deviceId: string | null;
    createdAt: Date;
}

@Injectable()
export class LoginHistoryService {
    private readonly logger = new Logger(LoginHistoryService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Record a login attempt
     */
    async recordLoginAttempt(info: LoginAttemptInfo): Promise<void> {
        await this.prisma.loginHistory.create({
            data: {
                userId: info.userId,
                status: info.status,
                ipAddress: info.ipAddress,
                userAgent: info.userAgent,
                deviceId: info.deviceId,
                failReason: info.failReason,
                location: undefined, // GeoIP lookup can be added later
            },
        });

        // Update user's failed login attempts counter if failed
        if (info.status !== 'SUCCESS') {
            await this.prisma.user.update({
                where: { id: info.userId },
                data: {
                    failedLoginAttempts: { increment: 1 },
                },
            });
        } else {
            // Reset failed attempts on successful login
            await this.prisma.user.update({
                where: { id: info.userId },
                data: {
                    failedLoginAttempts: 0,
                    lastLoginAt: new Date(),
                },
            });
        }
    }

    /**
     * Get login history for a user
     */
    async getLoginHistory(
        userId: string,
        limit: number = 20,
        offset: number = 0,
    ): Promise<LoginHistoryEntry[]> {
        const history = await this.prisma.loginHistory.findMany({
            where: { userId },
            orderBy: { createdAt: 'desc' },
            take: limit,
            skip: offset,
        });

        return history.map(entry => ({
            id: entry.id,
            status: entry.status,
            ipAddress: entry.ipAddress,
            userAgent: entry.userAgent,
            location: entry.location,
            deviceId: entry.deviceId,
            createdAt: entry.createdAt,
        }));
    }

    /**
     * Get failed login attempts count for a user within a time window
     */
    async getRecentFailedAttempts(
        userId: string,
        windowMinutes: number = 15,
    ): Promise<number> {
        const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);

        const count = await this.prisma.loginHistory.count({
            where: {
                userId,
                status: { not: 'SUCCESS' },
                createdAt: { gte: windowStart },
            },
        });

        return count;
    }

    /**
     * Check if account should be locked based on failed attempts
     */
    async shouldLockAccount(userId: string): Promise<boolean> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: {
                organization: {
                    include: {
                        passwordPolicy: true,
                    },
                },
            },
        });

        if (!user) return false;

        const threshold = user.organization?.passwordPolicy?.lockoutThreshold ?? 5;
        return user.failedLoginAttempts >= threshold;
    }

    /**
     * Lock user account
     */
    async lockAccount(userId: string, durationMinutes?: number): Promise<void> {
        // Get lockout duration from organization policy or use default
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: {
                organization: {
                    include: {
                        passwordPolicy: true,
                    },
                },
            },
        });

        const lockDuration = durationMinutes ??
            user?.organization?.passwordPolicy?.lockoutDurationMin ?? 30;

        const lockedUntil = new Date(Date.now() + lockDuration * 60 * 1000);

        await this.prisma.user.update({
            where: { id: userId },
            data: { lockedUntil },
        });

        this.logger.warn(`Account locked for user ${userId} until ${lockedUntil.toISOString()}`);
    }

    /**
     * Check if account is locked
     */
    async isAccountLocked(userId: string): Promise<boolean> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: { lockedUntil: true },
        });

        if (!user?.lockedUntil) return false;
        return user.lockedUntil > new Date();
    }

    /**
     * Unlock user account
     */
    async unlockAccount(userId: string): Promise<void> {
        await this.prisma.user.update({
            where: { id: userId },
            data: {
                lockedUntil: null,
                failedLoginAttempts: 0,
            },
        });
    }

    /**
     * Clean up old login history entries
     */
    async cleanupOldHistory(retentionDays: number = 90): Promise<number> {
        const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);

        const result = await this.prisma.loginHistory.deleteMany({
            where: {
                createdAt: { lt: cutoffDate },
            },
        });

        return result.count;
    }
}
