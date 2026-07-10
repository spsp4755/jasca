import {
    BadRequestException,
    Body,
    Controller,
    Get,
    Param,
    Post,
    Put,
    Query,
    Req,
    UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { Roles } from '../../common/decorators/roles.decorator';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import {
    ClustaraPayloadType,
    ClustaraService,
    ClustaraSettings,
    QueueDeliveryInput,
} from './clustara.service';

@ApiTags('Clustara Integration')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('clustara')
export class ClustaraController {
    constructor(private readonly clustaraService: ClustaraService) { }

    @Get('options')
    @Roles('VIEWER', 'DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN', 'SYSTEM_ADMIN')
    @ApiOperation({ summary: 'Get non-secret Clustara scan delivery options' })
    getPublicOptions() {
        return this.clustaraService.getPublicOptions();
    }

    @Get('settings')
    @Roles('SYSTEM_ADMIN', 'SECURITY_ADMIN')
    @ApiOperation({ summary: 'Get masked Clustara integration settings' })
    getSettings() {
        return this.clustaraService.getSettings(true);
    }

    @Put('settings')
    @Roles('SYSTEM_ADMIN', 'SECURITY_ADMIN')
    @ApiOperation({ summary: 'Update Clustara integration settings' })
    updateSettings(@Body() body: Partial<ClustaraSettings>) {
        return this.clustaraService.updateSettings(body);
    }

    @Post('test')
    @Roles('SYSTEM_ADMIN', 'SECURITY_ADMIN')
    @ApiOperation({ summary: 'Test Clustara DNS, TCP, and TLS connectivity without importing data' })
    testConnection(@Body() body: Partial<ClustaraSettings> = {}) {
        return this.clustaraService.testConnection(body);
    }

    @Get('deliveries')
    @Roles('SYSTEM_ADMIN', 'SECURITY_ADMIN')
    @ApiOperation({ summary: 'List recent Clustara deliveries' })
    listDeliveries(@Query('limit') limit?: string) {
        return this.clustaraService.listDeliveries(limit ? Number(limit) : 50);
    }

    @Get('scans/:scanId/deliveries')
    @Roles('VIEWER', 'DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN', 'SYSTEM_ADMIN')
    @ApiOperation({ summary: 'List Clustara deliveries for a scan' })
    getScanDeliveries(@Param('scanId') scanId: string, @Req() req: Request) {
        return this.clustaraService.getDeliveriesForScan(scanId, (req as any).user);
    }

    @Post('scans/:scanId/deliveries')
    @Roles('PROJECT_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN', 'SYSTEM_ADMIN')
    @ApiOperation({ summary: 'Queue a Trivy or SBOM delivery to Clustara' })
    queueDelivery(
        @Param('scanId') scanId: string,
        @Body() body: QueueDeliveryInput & { type: ClustaraPayloadType },
        @Req() req: Request,
    ) {
        if (!['TRIVY', 'SBOM'].includes(body.type)) {
            throw new BadRequestException('type은 TRIVY 또는 SBOM이어야 합니다.');
        }
        return this.clustaraService.queueDelivery(scanId, body.type, body, (req as any).user);
    }

    @Post('deliveries/:id/retry')
    @Roles('PROJECT_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN', 'SYSTEM_ADMIN')
    @ApiOperation({ summary: 'Retry a failed Clustara delivery' })
    retryDelivery(@Param('id') id: string, @Req() req: Request) {
        return this.clustaraService.retryDelivery(id, (req as any).user);
    }
}
