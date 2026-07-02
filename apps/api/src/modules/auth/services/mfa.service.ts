import { Injectable, Logger } from '@nestjs/common';
import { authenticator } from 'otplib';
import * as QRCode from 'qrcode';
import * as crypto from 'crypto';
import { PrismaService } from '../../../prisma/prisma.service';

export interface MfaSetupResult {
    secret: string;
    qrCodeUrl: string;
    backupCodes: string[];
}

@Injectable()
export class MfaService {
    private readonly logger = new Logger(MfaService.name);

    constructor(private readonly prisma: PrismaService) {
        // Configure TOTP settings
        authenticator.options = {
            window: 1, // Allow 1 step before/after for clock drift
            step: 30, // 30 second time step
        };
    }

    /**
     * Generate a new MFA secret and QR code for setup
     */
    async setupMfa(userId: string, userEmail: string): Promise<MfaSetupResult> {
        // Generate secret
        const secret = authenticator.generateSecret();

        // Generate backup codes
        const backupCodes = this.generateBackupCodes(8);
        const hashedBackupCodes = backupCodes.map(code =>
            crypto.createHash('sha256').update(code).digest('hex')
        );

        // Save MFA record (not enabled yet)
        await this.prisma.userMfa.upsert({
            where: { userId },
            create: {
                userId,
                secret: this.encryptSecret(secret),
                isEnabled: false,
                backupCodes: hashedBackupCodes,
            },
            update: {
                secret: this.encryptSecret(secret),
                isEnabled: false,
                backupCodes: hashedBackupCodes,
            },
        });

        // Generate QR code
        const otpauth = authenticator.keyuri(userEmail, 'JASCA', secret);
        const qrCodeUrl = await QRCode.toDataURL(otpauth);

        return {
            secret,
            qrCodeUrl,
            backupCodes,
        };
    }

    /**
     * Verify TOTP code and enable MFA
     */
    async verifyAndEnable(userId: string, token: string): Promise<boolean> {
        const mfa = await this.prisma.userMfa.findUnique({
            where: { userId },
        });

        if (!mfa) {
            return false;
        }

        const secret = this.decryptSecret(mfa.secret);
        const isValid = authenticator.verify({ token, secret });

        if (isValid) {
            await this.prisma.userMfa.update({
                where: { userId },
                data: {
                    isEnabled: true,
                    lastUsedAt: new Date(),
                },
            });
        }

        return isValid;
    }

    /**
     * Verify TOTP code for login
     */
    async verifyToken(userId: string, token: string): Promise<boolean> {
        const mfa = await this.prisma.userMfa.findUnique({
            where: { userId },
        });

        if (!mfa || !mfa.isEnabled) {
            return false;
        }

        const secret = this.decryptSecret(mfa.secret);
        const isValid = authenticator.verify({ token, secret });

        if (isValid) {
            await this.prisma.userMfa.update({
                where: { userId },
                data: { lastUsedAt: new Date() },
            });
        }

        return isValid;
    }

    /**
     * Verify backup code for login
     */
    async verifyBackupCode(userId: string, code: string): Promise<boolean> {
        const mfa = await this.prisma.userMfa.findUnique({
            where: { userId },
        });

        if (!mfa || !mfa.isEnabled) {
            return false;
        }

        const hashedCode = crypto.createHash('sha256').update(code).digest('hex');
        const codeIndex = mfa.backupCodes.findIndex(c => c === hashedCode);

        if (codeIndex === -1) {
            return false;
        }

        // Remove used backup code
        const updatedCodes = [...mfa.backupCodes];
        updatedCodes.splice(codeIndex, 1);

        await this.prisma.userMfa.update({
            where: { userId },
            data: {
                backupCodes: updatedCodes,
                lastUsedAt: new Date(),
            },
        });

        return true;
    }

    /**
     * Disable MFA for user
     */
    async disableMfa(userId: string): Promise<void> {
        await this.prisma.userMfa.update({
            where: { userId },
            data: { isEnabled: false },
        });
    }

    /**
     * Reset MFA (admin function)
     */
    async resetMfa(userId: string): Promise<void> {
        await this.prisma.userMfa.deleteMany({
            where: { userId },
        });
    }

    /**
     * Check if user has MFA enabled
     */
    async isMfaEnabled(userId: string): Promise<boolean> {
        const mfa = await this.prisma.userMfa.findUnique({
            where: { userId },
        });
        return mfa?.isEnabled ?? false;
    }

    /**
     * Regenerate backup codes
     */
    async regenerateBackupCodes(userId: string): Promise<string[]> {
        const backupCodes = this.generateBackupCodes(8);
        const hashedBackupCodes = backupCodes.map(code =>
            crypto.createHash('sha256').update(code).digest('hex')
        );

        await this.prisma.userMfa.update({
            where: { userId },
            data: { backupCodes: hashedBackupCodes },
        });

        return backupCodes;
    }

    private generateBackupCodes(count: number): string[] {
        const codes: string[] = [];
        for (let i = 0; i < count; i++) {
            // Format: XXXX-XXXX (8 alphanumeric characters)
            const code = crypto.randomBytes(4).toString('hex').toUpperCase();
            codes.push(`${code.slice(0, 4)}-${code.slice(4)}`);
        }
        return codes;
    }

    private encryptSecret(secret: string): string {
        // In production, use proper encryption with a secret key from env
        // For now, using base64 encoding as placeholder
        return Buffer.from(secret).toString('base64');
    }

    private decryptSecret(encryptedSecret: string): string {
        return Buffer.from(encryptedSecret, 'base64').toString('utf-8');
    }
}
