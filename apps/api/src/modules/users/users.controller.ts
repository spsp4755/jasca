import { Controller, Get, Post, Put, Delete, Param, Body, UseGuards, Query } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiQuery } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Permissions } from '../../common/decorators/permissions.decorator';
import { UsersService } from './users.service';

@ApiTags('Users')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UsersService) { }

    // Self-profile endpoints (no admin role required)
    @Get('me')
    @ApiOperation({ summary: 'Get current user profile' })
    async getProfile(@CurrentUser() user: { id: string }) {
        return this.usersService.findById(user.id);
    }

    @Put('me')
    @ApiOperation({ summary: 'Update current user profile' })
    async updateProfile(
        @CurrentUser() user: { id: string },
        @Body() dto: { name?: string },
    ) {
        return this.usersService.update(user.id, dto);
    }

    @Get('me/notification-settings')
    @ApiOperation({ summary: 'Get current user notification settings' })
    async getNotificationSettings(@CurrentUser() user: { id: string }) {
        return this.usersService.getNotificationSettings(user.id);
    }

    @Put('me/notification-settings')
    @ApiOperation({ summary: 'Update current user notification settings' })
    async updateNotificationSettings(
        @CurrentUser() user: { id: string },
        @Body() dto: { emailAlerts?: boolean; criticalOnly?: boolean; weeklyDigest?: boolean },
    ) {
        return this.usersService.updateNotificationSettings(user.id, dto);
    }

    // Admin endpoints
    @Get()
    @Permissions('user:read')
    @ApiOperation({ summary: 'Get all users' })
    @ApiQuery({ name: 'organizationId', required: false })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    @ApiQuery({ name: 'offset', required: false, type: Number })
    @ApiQuery({ name: 'search', required: false })
    @ApiQuery({ name: 'role', required: false, enum: ['SYSTEM_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN', 'PROJECT_ADMIN', 'DEVELOPER', 'VIEWER'] })
    @ApiQuery({ name: 'status', required: false, enum: ['ACTIVE', 'INACTIVE'] })
    async findAll(
        @Query('organizationId') organizationId?: string,
        @Query('limit') limit?: string,
        @Query('offset') offset?: string,
        @Query('search') search?: string,
        @Query('role') role?: string,
        @Query('status') status?: string,
        @CurrentUser() user?: any,
    ) {
        return this.usersService.findAll(user, organizationId, {
            limit: limit ? parseInt(limit, 10) : undefined,
            offset: offset ? parseInt(offset, 10) : undefined,
            search,
            role,
            status,
        });
    }

    @Post()
    @Permissions('user:create')
    @ApiOperation({ summary: 'Create user by admin' })
    async create(
        @CurrentUser() user: any,
        @Body() dto: { email: string; name: string; password: string; role?: string; status?: string; organizationId?: string },
    ) {
        return this.usersService.createUser(user, dto);
    }

    @Get(':id')
    @Permissions('user:read')
    @ApiOperation({ summary: 'Get user by ID' })
    async findById(@Param('id') id: string, @CurrentUser() user: any) {
        return this.usersService.findById(id, user);
    }

    @Put(':id')
    @Permissions('user:update')
    @ApiOperation({ summary: 'Update user' })
    async update(
        @Param('id') id: string,
        @CurrentUser() user: any,
        @Body() dto: { name?: string; role?: string; status?: string; organizationId?: string },
    ) {
        return this.usersService.updateUser(user, id, dto);
    }

    @Delete(':id')
    @Permissions('user:delete')
    @ApiOperation({ summary: 'Delete user' })
    async delete(@Param('id') id: string, @CurrentUser() user: any) {
        return this.usersService.deleteUser(user, id);
    }
}
