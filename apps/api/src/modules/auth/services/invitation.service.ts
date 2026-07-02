import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import * as crypto from 'crypto';
import { Role, InvitationStatus } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';

export interface InvitationInfo {
    id: string;
    email: string;
    organizationId: string;
    organizationName: string;
    role: Role;
    invitedByName: string;
    expiresAt: Date;
    status: InvitationStatus;
}

@Injectable()
export class InvitationService {
    private readonly logger = new Logger(InvitationService.name);
    private readonly INVITATION_EXPIRY_DAYS = 7;

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Create invitation for a user
     */
    async createInvitation(
        email: string,
        organizationId: string,
        invitedById: string,
        role: Role = 'DEVELOPER',
    ): Promise<{ token: string; expiresAt: Date }> {
        // Check if user already exists with this email
        const existingUser = await this.prisma.user.findUnique({
            where: { email },
        });

        if (existingUser?.organizationId === organizationId) {
            throw new BadRequestException('User is already a member of this organization');
        }

        // Check for existing pending invitation
        const existingInvitation = await this.prisma.userInvitation.findUnique({
            where: {
                email_organizationId: {
                    email,
                    organizationId,
                },
            },
        });

        if (existingInvitation && existingInvitation.status === 'PENDING') {
            // Delete old pending invitation
            await this.prisma.userInvitation.delete({
                where: { id: existingInvitation.id },
            });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + this.INVITATION_EXPIRY_DAYS);

        await this.prisma.userInvitation.create({
            data: {
                email,
                organizationId,
                invitedById,
                role,
                token,
                expiresAt,
                status: 'PENDING',
            },
        });

        return { token, expiresAt };
    }

    /**
     * Get invitation by token
     */
    async getInvitationByToken(token: string): Promise<InvitationInfo | null> {
        const invitation = await this.prisma.userInvitation.findUnique({
            where: { token },
            include: {
                organization: { select: { name: true } },
                invitedBy: { select: { name: true } },
            },
        });

        if (!invitation) {
            return null;
        }

        return {
            id: invitation.id,
            email: invitation.email,
            organizationId: invitation.organizationId,
            organizationName: invitation.organization.name,
            role: invitation.role,
            invitedByName: invitation.invitedBy.name,
            expiresAt: invitation.expiresAt,
            status: invitation.status,
        };
    }

    /**
     * Accept invitation and create user
     */
    async acceptInvitation(
        token: string,
        name: string,
        passwordHash: string,
    ): Promise<{ userId: string; organizationId: string }> {
        const invitation = await this.prisma.userInvitation.findUnique({
            where: { token },
        });

        if (!invitation) {
            throw new BadRequestException('Invalid invitation token');
        }

        if (invitation.status !== 'PENDING') {
            throw new BadRequestException(`Invitation has been ${invitation.status.toLowerCase()}`);
        }

        if (invitation.expiresAt < new Date()) {
            // Mark as expired
            await this.prisma.userInvitation.update({
                where: { id: invitation.id },
                data: { status: 'EXPIRED' },
            });
            throw new BadRequestException('Invitation has expired');
        }

        // Check if user already exists
        const existingUser = await this.prisma.user.findUnique({
            where: { email: invitation.email },
        });

        let userId: string;

        if (existingUser) {
            // Update existing user to join organization
            await this.prisma.user.update({
                where: { id: existingUser.id },
                data: {
                    organizationId: invitation.organizationId,
                    emailVerifiedAt: new Date(), // Email verified through invitation
                },
            });
            userId = existingUser.id;
        } else {
            // Create new user
            const user = await this.prisma.user.create({
                data: {
                    email: invitation.email,
                    name,
                    passwordHash,
                    organizationId: invitation.organizationId,
                    emailVerifiedAt: new Date(), // Email verified through invitation
                    isActive: true,
                },
            });
            userId = user.id;
        }

        // Assign role
        await this.prisma.userRole.create({
            data: {
                userId,
                role: invitation.role,
                scope: 'ORGANIZATION',
                scopeId: invitation.organizationId,
            },
        });

        // Mark invitation as accepted
        await this.prisma.userInvitation.update({
            where: { id: invitation.id },
            data: { status: 'ACCEPTED' },
        });

        return { userId, organizationId: invitation.organizationId };
    }

    /**
     * Revoke invitation
     */
    async revokeInvitation(invitationId: string): Promise<void> {
        await this.prisma.userInvitation.update({
            where: { id: invitationId },
            data: { status: 'REVOKED' },
        });
    }

    /**
     * Get all invitations for organization
     */
    async getOrganizationInvitations(
        organizationId: string,
        status?: InvitationStatus,
    ): Promise<InvitationInfo[]> {
        const invitations = await this.prisma.userInvitation.findMany({
            where: {
                organizationId,
                ...(status && { status }),
            },
            include: {
                organization: { select: { name: true } },
                invitedBy: { select: { name: true } },
            },
            orderBy: { createdAt: 'desc' },
        });

        return invitations.map(inv => ({
            id: inv.id,
            email: inv.email,
            organizationId: inv.organizationId,
            organizationName: inv.organization.name,
            role: inv.role,
            invitedByName: inv.invitedBy.name,
            expiresAt: inv.expiresAt,
            status: inv.status,
        }));
    }

    /**
     * Clean up expired invitations
     */
    async cleanupExpiredInvitations(): Promise<number> {
        const result = await this.prisma.userInvitation.updateMany({
            where: {
                status: 'PENDING',
                expiresAt: { lt: new Date() },
            },
            data: { status: 'EXPIRED' },
        });

        return result.count;
    }
}
