import {
    Controller,
    Get,
    Post,
    Delete,
    Param,
    Body,
    Query,
    UseGuards,
    UseInterceptors,
    UploadedFile,
    BadRequestException,
    Logger,
    Req,
    Res,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { SourceType } from '@prisma/client';
import {
    ApiTags,
    ApiBearerAuth,
    ApiOperation,
    ApiConsumes,
    ApiQuery,
    ApiSecurity,
    ApiBody,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { ScansService } from './scans.service';
import { UploadScanDto } from './dto/upload-scan.dto';
import { TrivyScanOptions, TrivyScanService } from './services/trivy-scan.service';
import { CheckovScanOptions, CheckovScanService } from './services/checkov-scan.service';
import { ZapScanOptions, ZapScanService } from './services/zap-scan.service';
import { SemgrepScanOptions, SemgrepScanService } from './services/semgrep-scan.service';
import { ScanArtifactService } from './services/scan-artifact.service';

const TRIVY_UPLOAD_ROOT = path.join(os.tmpdir(), 'jasca-trivy-uploads');
const MAX_TRIVY_UPLOAD_BYTES = parseSizeBytes(process.env.TRIVY_UPLOAD_MAX_BYTES, 200 * 1024 * 1024);

function parseSizeBytes(value: string | undefined, fallback: number): number {
    if (!value) return fallback;
    const trimmed = value.trim();
    const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/i);
    if (!match) return fallback;

    const amount = Number(match[1]);
    const unit = (match[2] || 'b').toLowerCase();
    const multiplier =
        unit === 'gb' ? 1024 ** 3 :
            unit === 'mb' ? 1024 ** 2 :
                unit === 'kb' ? 1024 :
                    1;

    return Math.floor(amount * multiplier);
}

function sanitizeUploadName(originalName: string): string {
    const baseName = path.basename(originalName || 'upload.bin');
    return baseName.replace(/[^a-zA-Z0-9._-]/g, '_');
}

function parseUploadedJson(buffer: Buffer): any {
    const contents = buffer.toString('utf-8').replace(/^\uFEFF/, '');
    try {
        return JSON.parse(contents);
    } catch {
        throw new BadRequestException('Uploaded file must be a valid JSON document');
    }
}

function parseBooleanField(value: unknown, defaultValue: boolean): boolean {
    if (value === undefined || value === null || value === '') {
        return defaultValue;
    }

    if (Array.isArray(value)) {
        return parseBooleanField(value[0], defaultValue);
    }

    return String(value).toLowerCase() === 'true';
}

function parseListField(value: unknown): string[] | undefined {
    if (value === undefined || value === null || value === '') {
        return undefined;
    }

    const values = Array.isArray(value) ? value : String(value).split(',');
    const normalized = values
        .flatMap((item) => String(item).split(','))
        .map((item) => item.trim())
        .filter(Boolean);

    return normalized.length ? normalized : undefined;
}

function parseTrivyScanOptions(body: any): TrivyScanOptions {
    return {
        scanMode: typeof body.scanMode === 'string' ? body.scanMode as TrivyScanOptions['scanMode'] : undefined,
        analysisStrategy: typeof body.analysisStrategy === 'string' ? body.analysisStrategy as TrivyScanOptions['analysisStrategy'] : undefined,
        rpmOsFamily: typeof body.rpmOsFamily === 'string' ? body.rpmOsFamily : undefined,
        rpmOsVersion: typeof body.rpmOsVersion === 'string' ? body.rpmOsVersion : undefined,
        offlineScan: parseBooleanField(body.offlineScan, true),
        skipDbUpdate: parseBooleanField(body.skipDbUpdate, true),
        skipJavaDbUpdate: parseBooleanField(body.skipJavaDbUpdate, true),
        ignoreUnfixed: parseBooleanField(body.ignoreUnfixed, false),
        severities: parseListField(body.severities),
        scanners: parseListField(body.scanners),
        timeout: typeof body.timeout === 'string' ? body.timeout : undefined,
    };
}

function parseSemgrepScanOptions(body: any): SemgrepScanOptions {
    const profile = ['all', 'security', 'custom-only'].includes(body.semgrepProfile)
        ? body.semgrepProfile
        : undefined;
    return {
        profile,
        languages: parseListField(body.semgrepLanguages),
        incremental: body.semgrepIncremental === 'true' || body.semgrepIncremental === true,
        timeout: typeof body.timeout === 'string' ? body.timeout : undefined,
    };
}

function parseCheckovScanOptions(body: any): CheckovScanOptions {
    return {
        frameworks: parseListField(body.checkovFrameworks || body.frameworks),
        checks: parseListField(body.checkovChecks || body.checks),
        skipChecks: parseListField(body.checkovSkipChecks || body.skipChecks),
        quiet: parseBooleanField(body.quiet, true),
        timeout: typeof body.checkovTimeout === 'string'
            ? body.checkovTimeout
            : typeof body.timeout === 'string'
                ? body.timeout
                : undefined,
    };
}

const trivyUploadStorage = diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(TRIVY_UPLOAD_ROOT, randomUUID());
        fs.mkdirSync(uploadDir, { recursive: true });
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, sanitizeUploadName(file.originalname));
    },
});

@ApiTags('Scans')
@Controller('scans')
export class ScansController {
    private readonly logger = new Logger(ScansController.name);

    constructor(
        private readonly scansService: ScansService,
        private readonly trivyScanService: TrivyScanService,
        private readonly checkovScanService: CheckovScanService,
        private readonly zapScanService: ZapScanService,
        private readonly semgrepScanService: SemgrepScanService,
        private readonly scanArtifactService: ScanArtifactService,
    ) { }

    @Get()
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Get all scan results' })
    @ApiQuery({ name: 'projectId', required: false, description: 'Project ID - if not provided, projectName and organizationId in body will be used to find/create project' })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    @ApiQuery({ name: 'offset', required: false, type: Number })
    async findAll(
        @Req() req: Request,
        @Query('projectId') projectId?: string,
        @Query('limit') limit?: string,
        @Query('offset') offset?: string,
    ) {
        return this.scansService.findAll(projectId, {
            limit: limit ? parseInt(limit, 10) : undefined,
            offset: offset ? parseInt(offset, 10) : undefined,
        }, (req as any).user);
    }

    @Get(':id')
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Get scan result by ID' })
    async findById(@Param('id') id: string, @Req() req: Request) {
        return this.scansService.findById(id, (req as any).user);
    }

    @Get(':id/best-fixes')
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Best-fix suggestions: group open findings by common root (package upgrade / code pattern)' })
    async getBestFixes(@Param('id') id: string, @Req() req: Request) {
        return this.scansService.getBestFixes(id, (req as any).user);
    }

    /**
     * Simple upload: Just send Trivy JSON directly
     * curl -X POST /api/scans/upload -H "Authorization: Bearer jasca_xxx" -H "Content-Type: application/json" -d @trivy.json
     */
    @Post('upload')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN')
    @ApiBearerAuth()
    @ApiSecurity('api-key')
    @ApiOperation({ summary: 'Upload a Trivy scan result directly as JSON body' })
    @ApiQuery({ name: 'projectId', required: false, description: 'Project ID' })
    @ApiQuery({ name: 'projectName', required: false, description: 'Project name (auto-create if not exists)' })
    @ApiQuery({ name: 'organizationId', required: false, description: 'Organization ID for auto-create (auto-filled from API token)' })
    @ApiQuery({ name: 'imageRef', required: false, description: 'Image reference' })
    @ApiQuery({ name: 'tag', required: false, description: 'Image tag' })
    @ApiBody({ description: 'Trivy JSON scan result' })
    async uploadDirect(
        @Query('projectId') projectId: string | undefined,
        @Query('projectName') projectName: string | undefined,
        @Query('organizationId') organizationIdParam: string | undefined,
        @Query('imageRef') imageRef: string | undefined,
        @Query('tag') tag: string | undefined,
        @Query('sourceType') sourceType: SourceType | undefined,
        @Body() body: any,
        @Req() req: Request,
    ) {
        const user = (req as any).user;
        
        // Use organizationId from query params, or fall back to API token's organizationId
        const organizationId = organizationIdParam || (user?.isApiToken ? user.organizationId : undefined);

        // Build DTO from query params
        const dto: UploadScanDto = {
            sourceType: sourceType && Object.values(SourceType).includes(sourceType)
                ? sourceType
                : SourceType.TRIVY_JSON,
            projectName: projectName,
            organizationId: organizationId,
            imageRef: imageRef,
            tag: tag,
        };

        // Capture source info - handle various IP formats
        const forwarded = req.headers['x-forwarded-for'];
        const forwardedIp = Array.isArray(forwarded) ? forwarded[0] : forwarded;
        let uploaderIp = forwardedIp || req.ip || req.socket?.remoteAddress;
        // Normalize localhost representations
        if (uploaderIp === '::1' || uploaderIp === '::ffff:127.0.0.1') {
            uploaderIp = '127.0.0.1';
        }
        uploaderIp = uploaderIp || 'unknown';
        const userAgent = req.headers['user-agent'] || 'API Client';
        const uploadedById = user?.id;

        // The body IS the Trivy result
        return this.scansService.uploadScan(projectId, dto, body, {
            uploaderIp,
            userAgent,
            uploadedById,
        }, user);
    }

    /**
     * File upload via multipart form
     */
    @Post('upload/file')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN')
    @ApiBearerAuth()
    @ApiSecurity('api-key')
    @ApiOperation({ summary: 'Upload a Trivy scan result as multipart file' })
    @ApiQuery({ name: 'projectId', required: false, description: 'Project ID - if not provided, use projectName & organizationId in body' })
    @ApiConsumes('multipart/form-data')
    @UseInterceptors(FileInterceptor('file'))
    async uploadFile(
        @Query('projectId') projectId: string | undefined,
        @Body() body: any,
        @UploadedFile() file: Express.Multer.File,
        @Req() req: Request,
    ) {
        if (!file) {
            throw new BadRequestException('No file uploaded');
        }

        // Build DTO from form fields (multipart form sends fields individually)
        const dto: UploadScanDto = {
            sourceType: body.sourceType || SourceType.TRIVY_JSON,
            projectName: body.projectName,
            organizationId: body.organizationId,
            imageRef: body.imageRef,
            imageDigest: body.imageDigest,
            tag: body.tag,
            commitHash: body.commitHash,
            branch: body.branch,
            ciPipeline: body.ciPipeline,
            ciJobUrl: body.ciJobUrl,
        };

        // Capture upload source info - handle various IP formats
        const forwarded = req.headers['x-forwarded-for'];
        const forwardedIp = Array.isArray(forwarded) ? forwarded[0] : forwarded;
        let uploaderIp = forwardedIp || req.ip || req.socket?.remoteAddress;
        // Normalize localhost representations
        if (uploaderIp === '::1' || uploaderIp === '::ffff:127.0.0.1') {
            uploaderIp = '127.0.0.1';
        }
        uploaderIp = uploaderIp || 'unknown';
        const userAgent = req.headers['user-agent'] || 'Browser Upload';
        const uploadedById = (req as any).user?.id;

        const rawResult = parseUploadedJson(file.buffer);
        return this.scansService.uploadScan(projectId, dto, rawResult, {
            uploaderIp,
            userAgent,
            uploadedById,
        }, (req as any).user);
    }

    /**
     * Scan an uploaded target file with a server-side scanner, then store the generated JSON result.
     */
    @Post('scan/file')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN')
    @ApiBearerAuth()
    @ApiSecurity('api-key')
    @ApiOperation({ summary: 'Upload a target file or archive and scan it with Trivy or Checkov' })
    @ApiQuery({ name: 'projectId', required: false, description: 'Project ID - if not provided, use projectName & organizationId in body' })
    @ApiConsumes('multipart/form-data')
    @UseInterceptors(FileInterceptor('file', {
        storage: trivyUploadStorage,
        limits: { fileSize: MAX_TRIVY_UPLOAD_BYTES },
    }))
    async scanUploadedFile(
        @Query('projectId') projectId: string | undefined,
        @Body() body: any,
        @UploadedFile() file: Express.Multer.File,
        @Req() req: Request,
    ) {
        if (!file) {
            throw new BadRequestException('No file uploaded');
        }

        const user = (req as any).user;
        const scanOperationId = typeof body.scanOperationId === 'string' ? body.scanOperationId : undefined;
        const requestedScanner = String(body.scanner || 'trivy').toLowerCase();
        const scanner = requestedScanner === 'checkov' || requestedScanner === 'semgrep' ? requestedScanner : 'trivy';
        let responseReady = false;
        if (scanOperationId) {
            req.on('close', () => {
                if (!responseReady && (req as any).aborted) {
                    if (scanner === 'checkov') {
                        this.checkovScanService.cancelScan(scanOperationId);
                    } else if (scanner === 'semgrep') {
                        this.semgrepScanService.cancelScan(scanOperationId);
                    } else {
                        this.trivyScanService.cancelScan(scanOperationId);
                    }
                }
            });
        }

        let generatedSbom: string | undefined;
        let rawResult: any;
        if (scanner === 'checkov') {
            rawResult = await this.checkovScanService.scanUploadedFile(
                file.path,
                parseCheckovScanOptions(body),
                scanOperationId,
            );
        } else if (scanner === 'semgrep') {
            rawResult = await this.semgrepScanService.scanUploadedFile(
                    file.path,
                    { ...parseSemgrepScanOptions(body), projectId },
                    scanOperationId,
                );
        } else {
            const trivyOutput = await this.trivyScanService.scanUploadedFile(
                    file.path,
                    parseTrivyScanOptions(body),
                    scanOperationId,
                );
            rawResult = trivyOutput.rawResult;
            generatedSbom = trivyOutput.generatedSbom;
        }

        if (scanner === 'trivy' && this.trivyScanService.isCancellationRequested(scanOperationId)) {
            throw new BadRequestException('Trivy scan was cancelled by the user');
        }
        const dto: UploadScanDto = {
            sourceType: scanner === 'checkov'
                ? SourceType.CHECKOV_JSON
                : scanner === 'semgrep'
                    ? SourceType.SARIF
                    : SourceType.TRIVY_JSON,
            projectName: body.projectName,
            organizationId: body.organizationId || user?.organizationId,
            imageRef: body.imageRef || file.originalname,
            imageDigest: body.imageDigest,
            tag: body.tag,
            commitHash: body.commitHash,
            branch: body.branch,
            ciPipeline: body.ciPipeline,
            ciJobUrl: body.ciJobUrl,
        };

        const forwarded = req.headers['x-forwarded-for'];
        const forwardedIp = Array.isArray(forwarded) ? forwarded[0] : forwarded;
        let uploaderIp = forwardedIp || req.ip || req.socket?.remoteAddress;
        if (uploaderIp === '::1' || uploaderIp === '::ffff:127.0.0.1') {
            uploaderIp = '127.0.0.1';
        }

        const savedScan = await this.scansService.uploadScan(projectId, dto, rawResult, {
            uploaderIp: uploaderIp || 'unknown',
            userAgent: req.headers['user-agent'] || `Browser ${scanner} Scan`,
            uploadedById: user?.id,
        }, user);
        if (scanner === 'trivy') {
            this.trivyScanService.markScanSaved(scanOperationId, savedScan.id);
        }

        if (scanner === 'trivy' && this.trivyScanService.isCancellationRequested(scanOperationId)) {
            if (scanOperationId) this.trivyScanService.consumeSavedScan(scanOperationId);
            await this.scansService.delete(savedScan.id, user).catch(() => undefined);
            throw new BadRequestException('Trivy scan was cancelled by the user');
        }

        if (generatedSbom) {
            try {
                await this.scanArtifactService.persistCycloneDx(savedScan.id, generatedSbom);
            } catch (error) {
                this.logger.warn(`Failed to persist generated SBOM for ${savedScan.id}: ${(error as Error).message}`);
            }
        }

        responseReady = true;
        return savedScan;
    }

    @Post('scan/zap')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN')
    @ApiBearerAuth()
    @ApiSecurity('api-key')
    @ApiOperation({ summary: 'Scan a web URL with OWASP ZAP and store the result' })
    @ApiQuery({ name: 'projectId', required: false, description: 'Project ID - if not provided, use projectName & organizationId in body' })
    async scanZapTarget(
        @Query('projectId') projectId: string | undefined,
        @Body() body: ZapScanOptions & {
            projectName?: string;
            organizationId?: string;
            imageRef?: string;
            tag?: string;
            scanOperationId?: string;
        },
        @Req() req: Request,
    ) {
        if (!body?.targetUrl || typeof body.targetUrl !== 'string') {
            throw new BadRequestException('targetUrl is required for ZAP scans');
        }

        const user = (req as any).user;
        const scanOperationId = typeof body.scanOperationId === 'string' ? body.scanOperationId : undefined;
        let responseReady = false;

        if (scanOperationId) {
            req.on('close', () => {
                if (!responseReady && (req as any).aborted) {
                    this.zapScanService.cancelScan(scanOperationId);
                }
            });
        }

        const rawResult = await this.zapScanService.scanUrl({
            targetUrl: body.targetUrl,
            scanMode: body.scanMode,
            confirmActiveScan: body.confirmActiveScan === true,
            authentication: body.authentication,
            targetProfileId: body.targetProfileId,
        }, scanOperationId);

        const dto: UploadScanDto = {
            sourceType: SourceType.ZAP_JSON,
            projectName: body.projectName,
            organizationId: body.organizationId || user?.organizationId,
            imageRef: body.imageRef || body.targetUrl,
            tag: body.tag,
        };

        const forwarded = req.headers['x-forwarded-for'];
        const forwardedIp = Array.isArray(forwarded) ? forwarded[0] : forwarded;
        let uploaderIp = forwardedIp || req.ip || req.socket?.remoteAddress;
        if (uploaderIp === '::1' || uploaderIp === '::ffff:127.0.0.1') {
            uploaderIp = '127.0.0.1';
        }

        const savedScan = await this.scansService.uploadScan(projectId, dto, rawResult, {
            uploaderIp: uploaderIp || 'unknown',
            userAgent: req.headers['user-agent'] || 'Browser ZAP Scan',
            uploadedById: user?.id,
        }, user);

        responseReady = true;
        return savedScan;
    }

    @Post('zap/test-connection')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('SECURITY_ADMIN')
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Test the configured OWASP ZAP server connection' })
    async testZapConnection() {
        return this.zapScanService.testConnection();
    }

    @Post('scan/cancel/:operationId')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN')
    @ApiBearerAuth()
    @ApiSecurity('api-key')
    @ApiOperation({ summary: 'Cancel a running Trivy scan' })
    async cancelTrivyScan(@Param('operationId') operationId: string, @Req() req: Request) {
        const trivyCancelled = this.trivyScanService.cancelScan(operationId);
        const checkovCancelled = this.checkovScanService.cancelScan(operationId);
        const zapCancelled = await this.zapScanService.cancelScan(operationId);
        const savedScanId = this.trivyScanService.consumeSavedScan(operationId);
        if (savedScanId) {
            await this.scansService.delete(savedScanId, (req as any).user).catch(() => undefined);
        }
        const cancelled = trivyCancelled || checkovCancelled || zapCancelled;
        return {
            cancelled,
            deletedSavedResult: !!savedScanId,
            message: cancelled ? 'Scan cancellation requested' : 'No running scan found for the operation ID',
        };
    }

    @Post('upload/json')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN')
    @ApiBearerAuth()
    @ApiSecurity('api-key')
    @ApiOperation({ summary: 'Upload a Trivy scan result with metadata wrapper' })
    @ApiQuery({ name: 'projectId', required: false, description: 'Project ID - if not provided, use projectName & organizationId in body' })
    async uploadJson(
        @Query('projectId') projectId: string | undefined,
        @Body() body: { metadata: UploadScanDto; result: any },
        @Req() req: Request,
    ) {
        // Capture upload source info - handle various IP formats
        const forwarded = req.headers['x-forwarded-for'];
        const forwardedIp = Array.isArray(forwarded) ? forwarded[0] : forwarded;
        let uploaderIp = forwardedIp || req.ip || req.socket?.remoteAddress;
        // Normalize localhost representations
        if (uploaderIp === '::1' || uploaderIp === '::ffff:127.0.0.1') {
            uploaderIp = '127.0.0.1';
        }
        uploaderIp = uploaderIp || 'unknown';
        const userAgent = req.headers['user-agent'] || 'API Client';
        const uploadedById = (req as any).user?.id;

        return this.scansService.uploadScan(projectId, body.metadata, body.result, {
            uploaderIp,
            userAgent,
            uploadedById,
        }, (req as any).user);
    }

    @Delete(':id')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('PROJECT_ADMIN', 'ORG_ADMIN')
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Delete a scan result' })
    async delete(@Param('id') id: string, @Req() req: Request) {
        return this.scansService.delete(id, (req as any).user);
    }

    @Get(':id/compare/:compareId')
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Compare two scans and get diff' })
    async compareScan(
        @Param('id') baseScanId: string,
        @Param('compareId') compareScanId: string,
        @Req() req: Request,
    ) {
        return this.scansService.compareScan(baseScanId, compareScanId, (req as any).user);
    }

    @Post('bulk-export')
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Export multiple scans as a single combined CSV or JSON file' })
    async bulkExport(
        @Body() body: { ids?: string[]; format?: string },
        @Req() req: Request,
        @Res() res: Response,
    ) {
        const ids = Array.isArray(body?.ids) ? body.ids : [];
        if (ids.length === 0) {
            throw new BadRequestException('ids must be a non-empty array of scan ids.');
        }
        const fmt = body?.format === 'json' ? 'json' : 'csv';
        const { content, fileName, contentType } = await this.scansService.bulkExport(ids, fmt, (req as any).user);
        res.set({
            'Content-Type': `${contentType}; charset=utf-8`,
            'Content-Disposition': `attachment; filename="${fileName}"`,
        });
        res.send(content);
    }

    @Post('bulk-delete')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('PROJECT_ADMIN', 'ORG_ADMIN')
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Delete multiple scan results at once' })
    async bulkDelete(@Body() body: { ids?: string[] }, @Req() req: Request) {
        const ids = Array.isArray(body?.ids) ? body.ids : [];
        if (ids.length === 0) {
            throw new BadRequestException('ids must be a non-empty array of scan ids.');
        }
        return this.scansService.bulkDelete(ids, (req as any).user);
    }

    @Get(':id/result/raw')
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Download the original Trivy JSON result for a scan' })
    async downloadRawResult(@Param('id') id: string, @Req() req: Request, @Res() res: Response) {
        const { json, fileName } = await this.scansService.getRawResult(id, (req as any).user);
        res.set({
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Disposition': `attachment; filename="${fileName}"`,
        });
        res.send(json);
    }

    @Get(':id/export/vulnerabilities')
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Export a scan\'s vulnerabilities as CSV or JSON' })
    @ApiQuery({ name: 'format', required: false, enum: ['csv', 'json'] })
    async exportVulnerabilities(
        @Param('id') id: string,
        @Query('format') format: string | undefined,
        @Req() req: Request,
        @Res() res: Response,
    ) {
        const fmt = format === 'json' ? 'json' : 'csv';
        const { content, fileName, contentType } = await this.scansService.exportVulnerabilities(id, fmt, (req as any).user);
        res.set({
            'Content-Type': `${contentType}; charset=utf-8`,
            'Content-Disposition': `attachment; filename="${fileName}"`,
        });
        res.send(content);
    }

    @Get(':id/export/licenses')
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Export a scan\'s package licenses as CSV or JSON' })
    @ApiQuery({ name: 'format', required: false, enum: ['csv', 'json'] })
    async exportLicenses(
        @Param('id') id: string,
        @Query('format') format: string | undefined,
        @Req() req: Request,
        @Res() res: Response,
    ) {
        const fmt = format === 'json' ? 'json' : 'csv';
        const { content, fileName, contentType } = await this.scansService.exportLicenses(id, fmt, (req as any).user);
        res.set({
            'Content-Type': `${contentType}; charset=utf-8`,
            'Content-Disposition': `attachment; filename="${fileName}"`,
        });
        res.send(content);
    }
}

