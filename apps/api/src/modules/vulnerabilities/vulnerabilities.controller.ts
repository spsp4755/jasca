import {
    Controller,
    Get,
    Post,
    Put,
    Param,
    Body,
    Query,
    UseGuards,
    BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiQuery } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { VulnerabilitiesService } from './vulnerabilities.service';
import { Severity, VulnStatus } from '@prisma/client';

@ApiTags('Vulnerabilities')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('vulnerabilities')
export class VulnerabilitiesController {
    constructor(private readonly vulnService: VulnerabilitiesService) { }

    @Get()
    @ApiOperation({ summary: 'Get all vulnerabilities with filters' })
    @ApiQuery({ name: 'projectId', required: false })
    @ApiQuery({ name: 'severity', required: false, isArray: true })
    @ApiQuery({ name: 'status', required: false, isArray: true })
    @ApiQuery({ name: 'cveId', required: false })
    @ApiQuery({ name: 'pkgName', required: false })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    @ApiQuery({ name: 'offset', required: false, type: Number })
    @ApiQuery({ name: 'sortBy', required: false, enum: ['severity', 'cveId', 'pkgName', 'status', 'createdAt'] })
    @ApiQuery({ name: 'sortOrder', required: false, enum: ['asc', 'desc'] })
    @ApiQuery({ name: 'latestScanOnly', required: false, type: Boolean, description: 'If true, only show vulnerabilities from the latest scan per project' })
    async findAll(
        @Query('projectId') projectId?: string,
        @Query('severity') severity?: Severity | Severity[],
        @Query('status') status?: VulnStatus | VulnStatus[],
        @Query('cveId') cveId?: string,
        @Query('pkgName') pkgName?: string,
        @Query('limit') limit?: string,
        @Query('offset') offset?: string,
        @Query('sortBy') sortBy?: 'severity' | 'cveId' | 'pkgName' | 'status' | 'createdAt',
        @Query('sortOrder') sortOrder?: 'asc' | 'desc',
        @Query('latestScanOnly') latestScanOnly?: string,
        @CurrentUser() user?: any,
    ) {
        const severityArr = severity
            ? Array.isArray(severity)
                ? severity
                : [severity]
            : undefined;
        const statusArr = status
            ? Array.isArray(status)
                ? status
                : [status]
            : undefined;

        return this.vulnService.findAll(
            { projectId, severity: severityArr, status: statusArr, cveId, pkgName },
            {
                limit: limit ? parseInt(limit, 10) : undefined,
                offset: offset ? parseInt(offset, 10) : undefined,
                sortBy,
                sortOrder,
                latestScanOnly: latestScanOnly === 'true',
            },
            user,
        );
    }


    @Get(':id')
    @ApiOperation({ summary: 'Get vulnerability by ID' })
    async findById(@Param('id') id: string, @CurrentUser() user?: any) {
        return this.vulnService.findById(id, user);
    }

    @Get('cve/:cveId')
    @ApiOperation({ summary: 'Get CVE details' })
    async findByCveId(@Param('cveId') cveId: string, @CurrentUser() user?: any) {
        return this.vulnService.findByCveId(cveId, user);
    }

    @Get('cve/:cveId/affected')
    @ApiOperation({ summary: 'Get all services affected by a CVE' })
    async findAffected(@Param('cveId') cveId: string, @CurrentUser() user?: any) {
        return this.vulnService.findAffectedByVuln(cveId, user);
    }

    @Put(':id/status')
    @ApiOperation({ summary: 'Update vulnerability status' })
    async updateStatus(
        @Param('id') id: string,
        @Body() body: { status: VulnStatus; comment?: string },
        @CurrentUser() user: any,
    ) {
        if (!user?.id) {
            throw new BadRequestException('User authentication required');
        }
        return this.vulnService.updateStatus(id, body.status, user.id, user.role, user);
    }

    @Get(':id/available-transitions')
    @ApiOperation({ summary: 'Get available status transitions for a vulnerability' })
    async getAvailableTransitions(
        @Param('id') id: string,
        @CurrentUser() user: any,
    ) {
        return this.vulnService.getAvailableTransitions(id, user.role, user);
    }

    @Put(':id/assign')
    @ApiOperation({ summary: 'Assign vulnerability to a user' })
    async assign(
        @Param('id') id: string,
        @Body() body: { assigneeId: string | null },
        @CurrentUser() user?: any,
    ) {
        return this.vulnService.assignUser(id, body.assigneeId, user);
    }

    @Post(':id/comments')
    @ApiOperation({ summary: 'Add comment to vulnerability' })
    async addComment(
        @Param('id') id: string,
        @Body() body: { content: string },
        @CurrentUser() user: any,
    ) {
        if (!user?.id) {
            throw new BadRequestException('User authentication required');
        }
        return this.vulnService.addComment(id, user.id, body.content, user);
    }

    @Get(':id/history')
    @ApiOperation({ summary: 'Get vulnerability history (status changes (& comments)' })
    async getHistory(@Param('id') id: string, @CurrentUser() user?: any) {
        return this.vulnService.getHistory(id, user);
    }
}

