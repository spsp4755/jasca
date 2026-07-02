import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../../../prisma/prisma.service';

export interface PasswordPolicyConfig {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecial: boolean;
    maxAgeDays: number | null;
    historyCount: number;
}

export interface PasswordValidationResult {
    isValid: boolean;
    errors: string[];
}

@Injectable()
export class PasswordPolicyService {
    private readonly logger = new Logger(PasswordPolicyService.name);
    private readonly BCRYPT_ROUNDS = 12; // Increased from 10 for better security

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Get password policy for an organization
     */
    async getPolicy(organizationId: string): Promise<PasswordPolicyConfig> {
        const policy = await this.prisma.passwordPolicy.findUnique({
            where: { organizationId },
        });

        // Return default policy if none configured
        return {
            minLength: policy?.minLength ?? 8,
            requireUppercase: policy?.requireUppercase ?? true,
            requireLowercase: policy?.requireLowercase ?? true,
            requireNumbers: policy?.requireNumbers ?? true,
            requireSpecial: policy?.requireSpecial ?? false,
            maxAgeDays: policy?.maxAgeDays ?? null,
            historyCount: policy?.historyCount ?? 5,
        };
    }

    /**
     * Validate password against organization policy
     */
    async validatePassword(
        password: string,
        organizationId?: string,
    ): Promise<PasswordValidationResult> {
        const policy = organizationId
            ? await this.getPolicy(organizationId)
            : this.getDefaultPolicy();

        const errors: string[] = [];

        if (password.length < policy.minLength) {
            errors.push(`Password must be at least ${policy.minLength} characters long`);
        }

        if (policy.requireUppercase && !/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }

        if (policy.requireLowercase && !/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }

        if (policy.requireNumbers && !/[0-9]/.test(password)) {
            errors.push('Password must contain at least one number');
        }

        if (policy.requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            errors.push('Password must contain at least one special character');
        }

        return {
            isValid: errors.length === 0,
            errors,
        };
    }

    /**
     * Check if password was recently used (against history)
     */
    async isPasswordInHistory(
        userId: string,
        password: string,
        organizationId?: string,
    ): Promise<boolean> {
        const policy = organizationId
            ? await this.getPolicy(organizationId)
            : this.getDefaultPolicy();

        const historyEntries = await this.prisma.passwordHistory.findMany({
            where: { userId },
            orderBy: { createdAt: 'desc' },
            take: policy.historyCount,
        });

        for (const entry of historyEntries) {
            const isMatch = await bcrypt.compare(password, entry.passwordHash);
            if (isMatch) {
                return true;
            }
        }

        return false;
    }

    /**
     * Hash password with bcrypt
     */
    async hashPassword(password: string): Promise<string> {
        return bcrypt.hash(password, this.BCRYPT_ROUNDS);
    }

    /**
     * Verify password against hash
     */
    async verifyPassword(password: string, hash: string): Promise<boolean> {
        return bcrypt.compare(password, hash);
    }

    /**
     * Add password to history
     */
    async addToHistory(userId: string, passwordHash: string): Promise<void> {
        await this.prisma.passwordHistory.create({
            data: {
                userId,
                passwordHash,
            },
        });

        // Clean up old history entries beyond the limit
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

        const historyCount = user?.organization?.passwordPolicy?.historyCount ?? 5;

        // Get IDs to delete (beyond history limit)
        const entriesToKeep = await this.prisma.passwordHistory.findMany({
            where: { userId },
            orderBy: { createdAt: 'desc' },
            take: historyCount,
            select: { id: true },
        });

        const idsToKeep = entriesToKeep.map(e => e.id);

        await this.prisma.passwordHistory.deleteMany({
            where: {
                userId,
                id: { notIn: idsToKeep },
            },
        });
    }

    /**
     * Check if password is expired
     */
    async isPasswordExpired(userId: string): Promise<boolean> {
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

        const maxAgeDays = user.organization?.passwordPolicy?.maxAgeDays;
        if (!maxAgeDays) return false; // No expiration policy

        const passwordChangedAt = user.passwordChangedAt || user.createdAt;
        const expirationDate = new Date(passwordChangedAt);
        expirationDate.setDate(expirationDate.getDate() + maxAgeDays);

        return new Date() > expirationDate;
    }

    /**
     * Change user password with validation
     */
    async changePassword(
        userId: string,
        currentPassword: string,
        newPassword: string,
    ): Promise<void> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            throw new BadRequestException('User not found');
        }

        // Verify current password
        const isCurrentValid = await this.verifyPassword(currentPassword, user.passwordHash);
        if (!isCurrentValid) {
            throw new BadRequestException('Current password is incorrect');
        }

        // Validate new password against policy
        const validation = await this.validatePassword(newPassword, user.organizationId ?? undefined);
        if (!validation.isValid) {
            throw new BadRequestException(validation.errors.join(', '));
        }

        // Check password history
        const inHistory = await this.isPasswordInHistory(userId, newPassword, user.organizationId ?? undefined);
        if (inHistory) {
            throw new BadRequestException('Password was recently used. Please choose a different password.');
        }

        // Hash and save new password
        const newHash = await this.hashPassword(newPassword);

        await this.prisma.user.update({
            where: { id: userId },
            data: {
                passwordHash: newHash,
                passwordChangedAt: new Date(),
            },
        });

        // Add old password to history
        await this.addToHistory(userId, user.passwordHash);
    }

    /**
     * Create or update password policy for organization
     */
    async upsertPolicy(
        organizationId: string,
        policy: Partial<PasswordPolicyConfig>,
    ): Promise<void> {
        await this.prisma.passwordPolicy.upsert({
            where: { organizationId },
            create: {
                organizationId,
                ...policy,
            },
            update: policy,
        });
    }

    private getDefaultPolicy(): PasswordPolicyConfig {
        return {
            minLength: 8,
            requireUppercase: true,
            requireLowercase: true,
            requireNumbers: true,
            requireSpecial: false,
            maxAgeDays: null,
            historyCount: 5,
        };
    }
}
