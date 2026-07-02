import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import * as crypto from 'crypto';
import { PrismaService } from '../../../prisma/prisma.service';

@Injectable()
export class EmailVerificationService {
    private readonly logger = new Logger(EmailVerificationService.name);
    private readonly TOKEN_EXPIRY_HOURS = 24;

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Create verification token for user
     */
    async createVerificationToken(userId: string): Promise<string> {
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + this.TOKEN_EXPIRY_HOURS);

        await this.prisma.emailVerification.upsert({
            where: { userId },
            create: {
                userId,
                token,
                expiresAt,
            },
            update: {
                token,
                expiresAt,
            },
        });

        return token;
    }

    /**
     * Verify email with token
     */
    async verifyEmail(token: string): Promise<{ success: boolean; userId?: string }> {
        const verification = await this.prisma.emailVerification.findUnique({
            where: { token },
            include: { user: true },
        });

        if (!verification) {
            return { success: false };
        }

        if (verification.expiresAt < new Date()) {
            // Token expired, delete it
            await this.prisma.emailVerification.delete({
                where: { id: verification.id },
            });
            return { success: false };
        }

        // Mark email as verified
        await this.prisma.user.update({
            where: { id: verification.userId },
            data: { emailVerifiedAt: new Date() },
        });

        // Delete verification record
        await this.prisma.emailVerification.delete({
            where: { id: verification.id },
        });

        return { success: true, userId: verification.userId };
    }

    /**
     * Check if user's email is verified
     */
    async isEmailVerified(userId: string): Promise<boolean> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: { emailVerifiedAt: true },
        });

        return user?.emailVerifiedAt !== null;
    }

    /**
     * Resend verification email
     */
    async resendVerification(userId: string): Promise<string> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            throw new BadRequestException('User not found');
        }

        if (user.emailVerifiedAt) {
            throw new BadRequestException('Email is already verified');
        }

        return this.createVerificationToken(userId);
    }

    /**
     * Get pending verification for user
     */
    async getPendingVerification(userId: string): Promise<{
        exists: boolean;
        expiresAt?: Date;
    }> {
        const verification = await this.prisma.emailVerification.findUnique({
            where: { userId },
        });

        if (!verification) {
            return { exists: false };
        }

        return {
            exists: true,
            expiresAt: verification.expiresAt,
        };
    }

    /**
     * Clean up expired verification tokens
     */
    async cleanupExpiredTokens(): Promise<number> {
        const result = await this.prisma.emailVerification.deleteMany({
            where: {
                expiresAt: { lt: new Date() },
            },
        });

        return result.count;
    }

    /**
     * Send verification email (placeholder - integrate with notification service)
     */
    async sendVerificationEmail(
        email: string,
        token: string,
        baseUrl: string,
    ): Promise<void> {
        const verificationUrl = `${baseUrl}/verify-email?token=${token}`;

        // TODO: Integrate with actual email service
        this.logger.log(`Verification email would be sent to ${email} with URL: ${verificationUrl}`);

        // In production, use nodemailer or a notification service to send email
    }
}
