import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export interface AuditLogEntry {
    userId?: string;
    organizationId?: string;
    action: string;
    resource: string;
    resourceId?: string;
    details?: Record<string, any>;
    ipAddress?: string;
    userAgent?: string;
}

@Injectable()
export class AuditService {
    constructor(private readonly prisma: PrismaService) { }

    async log(entry: AuditLogEntry) {
        return this.prisma.auditLog.create({
            data: {
                userId: entry.userId,
                organizationId: entry.organizationId,
                action: entry.action,
                resource: entry.resource,
                resourceId: entry.resourceId,
                details: entry.details,
                ipAddress: entry.ipAddress,
                userAgent: entry.userAgent,
            },
        });
    }

    async findAll(
        options: {
            organizationId?: string;
            userId?: string;
            action?: string;
            resource?: string;
            startDate?: Date;
            endDate?: Date;
            limit?: number;
            offset?: number;
        } = {},
    ) {
        const where: any = {};

        if (options.organizationId) where.organizationId = options.organizationId;
        if (options.userId) where.userId = options.userId;
        if (options.action) where.action = options.action;
        if (options.resource) where.resource = options.resource;

        if (options.startDate || options.endDate) {
            where.createdAt = {};
            if (options.startDate) where.createdAt.gte = options.startDate;
            if (options.endDate) where.createdAt.lte = options.endDate;
        }

        const [results, total] = await Promise.all([
            this.prisma.auditLog.findMany({
                where,
                include: {
                    user: { select: { id: true, name: true, email: true } },
                    organization: { select: { id: true, name: true } },
                },
                orderBy: { createdAt: 'desc' },
                take: options.limit || 50,
                skip: options.offset || 0,
            }),
            this.prisma.auditLog.count({ where }),
        ]);

        return { results, total };
    }
}
