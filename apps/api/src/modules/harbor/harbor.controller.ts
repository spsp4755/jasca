import { Body, Controller, Get, Headers, Param, Post, Put, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Roles } from '../../common/decorators/roles.decorator';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { HarborPushArtifactPayload, HarborScanService } from './harbor-scan.service';
import { HarborService, HarborSettings } from './harbor.service';

@ApiTags('Harbor')
@Controller('harbor')
export class HarborWebhookController {
    constructor(private readonly harborScanService: HarborScanService) {}

    @Post('webhook')
    @ApiOperation({ summary: 'Receive a Harbor default PUSH_ARTIFACT webhook' })
    webhook(
        @Headers('authorization') authorization: string | undefined,
        @Body() payload: HarborPushArtifactPayload,
    ) {
        return this.harborScanService.handleWebhook(authorization, payload);
    }
}

@ApiTags('Harbor')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('SYSTEM_ADMIN')
@Controller('harbor')
export class HarborController {
    constructor(private readonly harborService: HarborService) {}

    @Get('settings')
    @ApiOperation({ summary: 'Get Harbor settings without secrets' })
    getSettings() {
        return this.harborService.getSettings();
    }

    @Put('settings')
    @ApiOperation({ summary: 'Update Harbor settings' })
    updateSettings(@Body() settings: Partial<HarborSettings>) {
        return this.harborService.updateSettings(settings);
    }

    @Post('test-connection')
    @ApiOperation({ summary: 'Test the Harbor registry connection' })
    testConnection() {
        return this.harborService.testConnection();
    }

    @Get('projects')
    @ApiOperation({ summary: 'List configured Harbor projects' })
    listProjects() {
        return this.harborService.listProjects();
    }

    @Get('projects/:project/repositories')
    @ApiOperation({ summary: 'List Harbor repositories in a project' })
    listRepositories(@Param('project') project: string) {
        return this.harborService.listRepositories(project);
    }

    @Get('projects/:project/repositories/:repository/artifacts')
    @ApiOperation({ summary: 'List Harbor repository artifacts' })
    listArtifacts(@Param('project') project: string, @Param('repository') repository: string) {
        return this.harborService.listArtifacts(project, repository);
    }
}
