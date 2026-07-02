import {
    Controller,
    Get,
    Post,
    Query,
    Param,
    UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiQuery } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { ComplianceService } from './compliance.service';
import { CurrentUser } from '../../common/decorators/current-user.decorator';

@ApiTags('Compliance')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('compliance')
export class ComplianceController {
    constructor(private readonly complianceService: ComplianceService) { }

    @Get('report')
    @ApiOperation({ summary: 'Generate compliance report' })
    @ApiQuery({ name: 'reportType', required: false, enum: ['PCI-DSS', 'SOC2', 'HIPAA', 'ISO27001', 'GENERAL'] })
    async generateReport(
        @CurrentUser() user: { organizationId: string },
        @Query('reportType') reportType?: 'PCI-DSS' | 'SOC2' | 'HIPAA' | 'ISO27001' | 'GENERAL',
    ) {
        return this.complianceService.generateComplianceReport(
            user.organizationId,
            reportType || 'GENERAL',
        );
    }

    @Get('violations')
    @ApiOperation({ summary: 'Get policy violation history' })
    @ApiQuery({ name: 'days', required: false, type: Number })
    async getViolations(
        @CurrentUser() user: { organizationId: string },
        @Query('days') days?: string,
    ) {
        return this.complianceService.getViolationHistory(
            user.organizationId,
            days ? parseInt(days, 10) : 30,
        );
    }

    @Post('violations/track/:scanResultId')
    @ApiOperation({ summary: 'Track policy violations for a scan' })
    async trackViolations(@Param('scanResultId') scanResultId: string) {
        return this.complianceService.trackPolicyViolations(scanResultId);
    }

    @Get('report/:id/export')
    @ApiOperation({ summary: 'Export compliance report' })
    @ApiQuery({ name: 'format', required: false, enum: ['JSON', 'PDF', 'CSV'] })
    async exportReport(
        @CurrentUser() user: { organizationId: string },
        @Query('format') format?: 'JSON' | 'PDF' | 'CSV',
    ) {
        const report = await this.complianceService.generateComplianceReport(
            user.organizationId,
            'GENERAL',
        );
        return this.complianceService.exportReport(report, format || 'JSON');
    }
}
