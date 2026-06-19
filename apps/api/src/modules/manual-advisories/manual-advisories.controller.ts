import { Body, Controller, Delete, Get, Param, Post, Put, Query, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { Severity } from '@prisma/client';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { ManualAdvisoriesService, ManualAdvisoryDto } from './manual-advisories.service';

function parseBoolean(value?: string): boolean | undefined {
    if (value === undefined) return undefined;
    return value.toLowerCase() === 'true';
}

@ApiTags('Manual Advisories')
@ApiBearerAuth()
@ApiSecurity('api-key')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('SYSTEM_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN')
@Controller('manual-advisories')
export class ManualAdvisoriesController {
    constructor(private readonly manualAdvisoriesService: ManualAdvisoriesService) { }

    @Get()
    @ApiOperation({ summary: 'List manual vulnerability advisories' })
    @ApiQuery({ name: 'organizationId', required: false })
    @ApiQuery({ name: 'projectId', required: false })
    @ApiQuery({ name: 'isActive', required: false })
    async findAll(
        @CurrentUser() user: any,
        @Query('organizationId') organizationId?: string,
        @Query('projectId') projectId?: string,
        @Query('isActive') isActive?: string,
    ) {
        return this.manualAdvisoriesService.findAll(user, {
            organizationId,
            projectId,
            isActive: parseBoolean(isActive),
        });
    }

    @Post()
    @ApiOperation({ summary: 'Create a manual vulnerability advisory' })
    async create(@Body() dto: ManualAdvisoryDto, @CurrentUser() user: any) {
        return this.manualAdvisoriesService.create(this.normalizeDto(dto), user);
    }

    @Put(':id')
    @ApiOperation({ summary: 'Update a manual vulnerability advisory' })
    async update(
        @Param('id') id: string,
        @Body() dto: Partial<ManualAdvisoryDto>,
        @CurrentUser() user: any,
    ) {
        return this.manualAdvisoriesService.update(id, this.normalizeDto(dto), user);
    }

    @Delete(':id')
    @ApiOperation({ summary: 'Delete a manual vulnerability advisory' })
    async remove(@Param('id') id: string, @CurrentUser() user: any) {
        return this.manualAdvisoriesService.remove(id, user);
    }

    private normalizeDto<T extends Partial<ManualAdvisoryDto>>(dto: T): T {
        const rawReferences = (dto as any).references;
        return {
            ...dto,
            severity: dto.severity ? String(dto.severity).toUpperCase() as Severity : dto.severity,
            references: Array.isArray(rawReferences)
                ? rawReferences
                : typeof rawReferences === 'string'
                    ? String(rawReferences).split(/\r?\n/)
                    : rawReferences,
        };
    }
}
