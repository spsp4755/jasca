import { Injectable, NotFoundException, ConflictException, ForbiddenException } from '@nestjs/common';
import { Role } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { CreateOrganizationDto } from './dto/create-organization.dto';

type RequestUser = {
    id: string;
    organizationId?: string | null;
    roles?: Array<{ role: string } | string>;
};

@Injectable()
export class OrganizationsService {
    constructor(private readonly prisma: PrismaService) { }

    async findAll(actor?: RequestUser) {
        const where = this.isSystemAdmin(actor)
            ? undefined
            : actor?.organizationId
                ? { id: actor.organizationId }
                : undefined;

        return this.prisma.organization.findMany({
            where,
            include: {
                _count: {
                    select: { projects: true, users: true },
                },
            },
            orderBy: { createdAt: 'desc' },
        });
    }

    async findById(id: string, actor?: RequestUser) {
        this.assertOrganizationScope(actor, id);
        const org = await this.prisma.organization.findUnique({
            where: { id },
            include: {
                projects: true,
                users: { include: { roles: true } },
                _count: {
                    select: { projects: true, users: true },
                },
            },
        });

        if (!org) {
            throw new NotFoundException('Organization not found');
        }

        return org;
    }

    async findBySlug(slug: string) {
        return this.prisma.organization.findUnique({
            where: { slug },
        });
    }

    async create(dto: CreateOrganizationDto) {
        const existing = await this.findBySlug(dto.slug);
        if (existing) {
            throw new ConflictException('Organization slug already exists');
        }

        return this.prisma.organization.create({
            data: {
                name: dto.name,
                slug: dto.slug,
                description: dto.description,
            },
        });
    }

    async update(id: string, data: Partial<CreateOrganizationDto>, actor?: RequestUser) {
        await this.findById(id, actor);

        return this.prisma.organization.update({
            where: { id },
            data,
        });
    }

    async delete(id: string, actor?: RequestUser) {
        await this.findById(id, actor);

        return this.prisma.organization.delete({
            where: { id },
        });
    }

    private isSystemAdmin(actor?: RequestUser) {
        const roles = (actor?.roles || []).map((role) => (typeof role === 'string' ? role : role.role));
        return roles.includes(Role.SYSTEM_ADMIN);
    }

    private assertOrganizationScope(actor: RequestUser | undefined, organizationId: string) {
        if (!actor || this.isSystemAdmin(actor)) {
            return;
        }

        if (actor.organizationId && actor.organizationId !== organizationId) {
            throw new ForbiddenException('You can only access your organization');
        }
    }
}
