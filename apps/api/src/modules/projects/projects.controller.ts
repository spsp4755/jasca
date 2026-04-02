import {
    Controller,
    Get,
    Post,
    Put,
    Delete,
    Param,
    Body,
    Query,
    UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiQuery } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Permissions } from '../../common/decorators/permissions.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { ProjectsService } from './projects.service';
import { CreateProjectDto } from './dto/create-project.dto';

@ApiTags('Projects')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('projects')
export class ProjectsController {
    constructor(private readonly projectsService: ProjectsService) { }

    @Get()
    @Permissions('project:read')
    @ApiOperation({ summary: 'Get all projects' })
    @ApiQuery({ name: 'organizationId', required: false })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    @ApiQuery({ name: 'offset', required: false, type: Number })
    @ApiQuery({ name: 'search', required: false })
    @ApiQuery({ name: 'sortBy', required: false, enum: ['name', 'createdAt', 'riskLevel'] })
    @ApiQuery({ name: 'sortOrder', required: false, enum: ['asc', 'desc'] })
    @ApiQuery({ name: 'riskLevel', required: false, enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'] })
    async findAll(
        @Query('organizationId') organizationId?: string,
        @Query('limit') limit?: string,
        @Query('offset') offset?: string,
        @Query('search') search?: string,
        @Query('sortBy') sortBy?: 'name' | 'createdAt' | 'riskLevel',
        @Query('sortOrder') sortOrder?: 'asc' | 'desc',
        @Query('riskLevel') riskLevel?: string,
        @CurrentUser() user?: any,
    ) {
        return this.projectsService.findAll(user, organizationId, {
            limit: limit ? parseInt(limit, 10) : undefined,
            offset: offset ? parseInt(offset, 10) : undefined,
            search,
            sortBy,
            sortOrder,
            riskLevel,
        });
    }


    @Get(':id/vulnerability-trend')
    @Permissions('project:read')
    @ApiOperation({ summary: 'Get vulnerability trend for a project' })
    @ApiQuery({ name: 'days', required: false })
    async getVulnerabilityTrend(
        @Param('id') id: string,
        @Query('days') days?: string,
        @CurrentUser() user?: any,
    ) {
        return this.projectsService.getVulnerabilityTrend(id, parseInt(days || '30'), user);
    }

    @Get(':id')
    @Permissions('project:read')
    @ApiOperation({ summary: 'Get project by ID' })
    async findById(@Param('id') id: string, @CurrentUser() user?: any) {
        return this.projectsService.findById(id, user);
    }


    @Post()
    @Permissions('project:create')
    @ApiOperation({ summary: 'Create a new project' })
    async create(
        @Query('organizationId') organizationId: string,
        @Body() dto: CreateProjectDto,
        @CurrentUser() user: any,
    ) {
        return this.projectsService.create(user, organizationId, dto);
    }

    @Put(':id')
    @Permissions('project:update')
    @ApiOperation({ summary: 'Update a project' })
    async update(@Param('id') id: string, @Body() dto: Partial<CreateProjectDto>, @CurrentUser() user: any) {
        return this.projectsService.update(user, id, dto);
    }

    @Delete(':id')
    @Permissions('project:delete')
    @ApiOperation({ summary: 'Delete a project' })
    async delete(@Param('id') id: string, @CurrentUser() user: any) {
        return this.projectsService.delete(user, id);
    }
}
