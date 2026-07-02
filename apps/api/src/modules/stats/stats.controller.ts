import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiQuery } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { StatsService } from './stats.service';

@ApiTags('Statistics')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('stats')
export class StatsController {
    constructor(private readonly statsService: StatsService) { }

    @Get('overview')
    @ApiOperation({ summary: 'Get vulnerability overview statistics' })
    @ApiQuery({ name: 'organizationId', required: false })
    async getOverview(@Query('organizationId') organizationId?: string, @CurrentUser() user?: any) {
        return this.statsService.getOverview(organizationId, user);
    }

    @Get('by-project')
    @ApiOperation({ summary: 'Get statistics by project' })
    @ApiQuery({ name: 'organizationId', required: false })
    async getByProject(@Query('organizationId') organizationId?: string, @CurrentUser() user?: any) {
        return this.statsService.getByProject(organizationId, user);
    }

    @Get('trend')
    @ApiOperation({ summary: 'Get vulnerability trend over time' })
    @ApiQuery({ name: 'organizationId', required: false })
    @ApiQuery({ name: 'days', required: false, type: Number })
    async getTrend(
        @Query('organizationId') organizationId?: string,
        @Query('days') days?: string,
        @CurrentUser() user?: any,
    ) {
        return this.statsService.getTrend(
            organizationId,
            days ? parseInt(days, 10) : 30,
            user,
        );
    }
}
