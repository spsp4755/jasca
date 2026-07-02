import { Body, Controller, Get, Param, Post, Put, Query, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { Severity, VulnPortalIntelType } from '@prisma/client';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { VulnPortalService, VulnPortalSettings } from './vuln-portal.service';

@ApiTags('Vuln Portal Integration')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('SYSTEM_ADMIN', 'SECURITY_ADMIN')
@Controller('vuln-portal')
export class VulnPortalController {
    constructor(private readonly vulnPortalService: VulnPortalService) { }

    @Get('settings')
    @ApiOperation({ summary: 'Get vuln-portal integration settings' })
    async getSettings() {
        return this.vulnPortalService.getSettings(true);
    }

    @Put('settings')
    @ApiOperation({ summary: 'Update vuln-portal integration settings' })
    async updateSettings(@Body() body: Partial<VulnPortalSettings>) {
        return this.vulnPortalService.updateSettings(body);
    }

    @Post('test')
    @ApiOperation({ summary: 'Test vuln-portal API connection' })
    async testConnection(@Body() body?: Partial<VulnPortalSettings>) {
        return this.vulnPortalService.testConnection(body);
    }

    @Post('sync')
    @ApiOperation({ summary: 'Run vuln-portal synchronization now' })
    async syncNow() {
        return this.vulnPortalService.syncNow();
    }

    @Get('status')
    @ApiOperation({ summary: 'Get vuln-portal integration status' })
    async getStatus() {
        return this.vulnPortalService.getStatus();
    }

    @Get('logs')
    @ApiOperation({ summary: 'Get vuln-portal synchronization logs' })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    async getLogs(@Query('limit') limit?: string) {
        return this.vulnPortalService.getLogs(limit ? parseInt(limit, 10) : 20);
    }

    @Get('intel')
    @ApiOperation({ summary: 'List synchronized vuln-portal intelligence' })
    @ApiQuery({ name: 'type', required: false, enum: VulnPortalIntelType })
    @ApiQuery({ name: 'keyword', required: false })
    @ApiQuery({ name: 'severity', required: false, enum: Severity })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    @ApiQuery({ name: 'offset', required: false, type: Number })
    async listIntel(
        @Query('type') type?: VulnPortalIntelType,
        @Query('keyword') keyword?: string,
        @Query('severity') severity?: Severity,
        @Query('limit') limit?: string,
        @Query('offset') offset?: string,
    ) {
        return this.vulnPortalService.listIntel({
            type,
            keyword,
            severity,
            limit: limit ? parseInt(limit, 10) : undefined,
            offset: offset ? parseInt(offset, 10) : undefined,
        });
    }

    @Get('intel/cve/:cveId')
    @ApiOperation({ summary: 'Get synchronized vuln-portal intelligence for a CVE' })
    async findByCveId(@Param('cveId') cveId: string) {
        return this.vulnPortalService.findByCveId(cveId);
    }
}
