import {
    Controller,
    Get,
    Post,
    Put,
    Delete,
    Param,
    Body,
    UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Permissions } from '../../common/decorators/permissions.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { OrganizationsService } from './organizations.service';
import { CreateOrganizationDto } from './dto/create-organization.dto';

@ApiTags('Organizations')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('organizations')
export class OrganizationsController {
    constructor(private readonly organizationsService: OrganizationsService) { }

    @Get()
    @Permissions('org:read')
    @ApiOperation({ summary: 'Get all organizations' })
    async findAll(@CurrentUser() user: any) {
        return this.organizationsService.findAll(user);
    }

    @Get(':id')
    @Permissions('org:read')
    @ApiOperation({ summary: 'Get organization by ID' })
    async findById(@Param('id') id: string, @CurrentUser() user: any) {
        return this.organizationsService.findById(id, user);
    }

    @Post()
    @Permissions('org:create')
    @ApiOperation({ summary: 'Create a new organization' })
    async create(@Body() dto: CreateOrganizationDto) {
        return this.organizationsService.create(dto);
    }

    @Put(':id')
    @Permissions('org:update')
    @ApiOperation({ summary: 'Update an organization' })
    async update(@Param('id') id: string, @Body() dto: Partial<CreateOrganizationDto>, @CurrentUser() user: any) {
        return this.organizationsService.update(id, dto, user);
    }

    @Delete(':id')
    @Permissions('org:delete')
    @ApiOperation({ summary: 'Delete an organization' })
    async delete(@Param('id') id: string, @CurrentUser() user: any) {
        return this.organizationsService.delete(id, user);
    }
}
