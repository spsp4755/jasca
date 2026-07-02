import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { NormalizationEngineService } from './normalization-engine.service';
import { NormalizeResultDto, NormalizedResultResponseDto } from './dto/normalize.dto';
import { NormalizedScanResult } from './schemas/normalized-vulnerability.schema';

@ApiTags('Normalization')
@Controller('normalization')
export class NormalizationController {
    constructor(private readonly normalizationService: NormalizationEngineService) { }

    @Post('normalize')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Normalize scan result to internal schema' })
    @ApiResponse({
        status: 200,
        description: 'Normalized scan result',
        type: NormalizedResultResponseDto,
    })
    async normalize(
        @Body() body: { rawResult: any; options: NormalizeResultDto },
    ): Promise<NormalizedScanResult> {
        return this.normalizationService.normalize(
            body.rawResult,
            body.options.sourceFormat,
            {
                schemaVersion: body.options.schemaVersion,
                scannerVersion: body.options.scannerVersion,
            },
        );
    }

    @Post('detect-schema')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Detect schema version from raw Trivy result' })
    async detectSchema(@Body() body: { rawResult: any }): Promise<{ schemaVersion: string }> {
        const version = this.normalizationService.detectTrivySchemaVersion(body.rawResult);
        return { schemaVersion: version };
    }
}
