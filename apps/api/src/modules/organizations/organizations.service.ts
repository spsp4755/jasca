import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { CreateOrganizationDto } from './dto/create-organization.dto';
import {
    RequestUser,
    assertOrganizationAccess,
    assertOrganizationManager,
    getScopedOrganizationIds,
    isSystemAdmin,
} from '../../common/authz/access-control';

@Injectable()
export class OrganizationsService {
    constructor(private readonly prisma: PrismaService) { }

    async findAll(currentUser?: RequestUser) {
        const scopedOrganizationIds = currentUser ? getScopedOrganizationIds(currentUser) : undefined;
        const where = scopedOrganizationIds
            ? { id: { in: scopedOrganizationIds } }
            : {};

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

    async findById(id: string, currentUser?: RequestUser) {
        if (currentUser && !isSystemAdmin(currentUser)) {
            assertOrganizationAccess(currentUser, id);
        }

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

    async update(id: string, data: Partial<CreateOrganizationDto>, currentUser?: RequestUser) {
        await this.findById(id, currentUser);
        if (currentUser) {
            assertOrganizationManager(currentUser, id, ['ORG_ADMIN']);
        }

        return this.prisma.organization.update({
            where: { id },
            data,
        });
    }

    async delete(id: string) {
        await this.findById(id);

        return this.prisma.organization.delete({
            where: { id },
        });
    }
}
