import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import { PrismaService } from '../../../prisma/prisma.service';

export interface DeviceInfo {
    userAgent?: string;
    platform?: string;
    browser?: string;
    deviceId?: string;
}

export interface SessionInfo {
    id: string;
    deviceInfo: DeviceInfo | null;
    ipAddress: string | null;
    createdAt: Date;
    lastActiveAt: Date;
    isActive: boolean;
    isCurrent: boolean;
}

@Injectable()
export class SessionService {
    private readonly logger = new Logger(SessionService.name);
    private readonly SESSION_EXPIRY_DAYS = 7;

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Create a new session for user
     */
    async createSession(
        userId: string,
        refreshToken: string,
        ipAddress?: string,
        deviceInfo?: DeviceInfo,
    ): Promise<string> {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + this.SESSION_EXPIRY_DAYS);

        const hashedToken = this.hashToken(refreshToken);

        const session = await this.prisma.userSession.create({
            data: {
                userId,
                refreshToken: hashedToken,
                ipAddress,
                deviceInfo: deviceInfo as any,
                expiresAt,
                isActive: true,
            },
        });

        // Check for new device and potentially send alert
        if (deviceInfo?.deviceId) {
            await this.checkNewDevice(userId, deviceInfo.deviceId, ipAddress);
        }

        return session.id;
    }

    /**
     * Validate and get session by refresh token
     */
    async validateSession(refreshToken: string): Promise<{
        userId: string;
        sessionId: string;
    } | null> {
        const hashedToken = this.hashToken(refreshToken);

        const session = await this.prisma.userSession.findUnique({
            where: { refreshToken: hashedToken },
        });

        if (!session) {
            return null;
        }

        if (!session.isActive || session.expiresAt < new Date()) {
            // Session expired or deactivated
            await this.invalidateSession(session.id);
            return null;
        }

        // Update last active time
        await this.prisma.userSession.update({
            where: { id: session.id },
            data: { lastActiveAt: new Date() },
        });

        return {
            userId: session.userId,
            sessionId: session.id,
        };
    }

    /**
     * Get all active sessions for a user
     */
    async getUserSessions(userId: string, currentSessionId?: string): Promise<SessionInfo[]> {
        const sessions = await this.prisma.userSession.findMany({
            where: {
                userId,
                isActive: true,
                expiresAt: { gt: new Date() },
            },
            orderBy: { lastActiveAt: 'desc' },
        });

        return sessions.map(session => ({
            id: session.id,
            deviceInfo: session.deviceInfo as DeviceInfo | null,
            ipAddress: session.ipAddress,
            createdAt: session.createdAt,
            lastActiveAt: session.lastActiveAt,
            isActive: session.isActive,
            isCurrent: session.id === currentSessionId,
        }));
    }

    /**
     * Invalidate a specific session
     */
    async invalidateSession(sessionId: string): Promise<void> {
        await this.prisma.userSession.update({
            where: { id: sessionId },
            data: { isActive: false },
        });
    }

    /**
     * Invalidate all sessions for a user (force logout all devices)
     */
    async invalidateAllSessions(userId: string, exceptSessionId?: string): Promise<number> {
        const result = await this.prisma.userSession.updateMany({
            where: {
                userId,
                isActive: true,
                ...(exceptSessionId && { id: { not: exceptSessionId } }),
            },
            data: { isActive: false },
        });

        return result.count;
    }

    /**
     * Rotate refresh token (generate new one and invalidate old)
     */
    async rotateRefreshToken(
        oldRefreshToken: string,
        newRefreshToken: string,
    ): Promise<boolean> {
        const hashedOldToken = this.hashToken(oldRefreshToken);
        const hashedNewToken = this.hashToken(newRefreshToken);

        const session = await this.prisma.userSession.findUnique({
            where: { refreshToken: hashedOldToken },
        });

        if (!session || !session.isActive) {
            return false;
        }

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + this.SESSION_EXPIRY_DAYS);

        await this.prisma.userSession.update({
            where: { id: session.id },
            data: {
                refreshToken: hashedNewToken,
                expiresAt,
                lastActiveAt: new Date(),
            },
        });

        return true;
    }

    /**
     * Clean up expired sessions
     */
    async cleanupExpiredSessions(): Promise<number> {
        const result = await this.prisma.userSession.deleteMany({
            where: {
                OR: [
                    { expiresAt: { lt: new Date() } },
                    {
                        isActive: false,
                        lastActiveAt: {
                            lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days ago
                        },
                    },
                ],
            },
        });

        return result.count;
    }

    /**
     * Check if this is a new device for the user
     */
    private async checkNewDevice(
        userId: string,
        deviceId: string,
        ipAddress?: string,
    ): Promise<boolean> {
        const existingSession = await this.prisma.userSession.findFirst({
            where: {
                userId,
                deviceInfo: {
                    path: ['deviceId'],
                    equals: deviceId,
                },
            },
        });

        if (!existingSession) {
            this.logger.log(`New device login detected for user ${userId} from IP ${ipAddress}`);
            // TODO: Here you would trigger a notification to the user
            return true;
        }

        return false;
    }

    private hashToken(token: string): string {
        return crypto.createHash('sha256').update(token).digest('hex');
    }
}
