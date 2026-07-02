import { IsString, IsOptional, IsEnum } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum NormalizationFormat {
    TRIVY_JSON = 'TRIVY_JSON',
    TRIVY_SARIF = 'TRIVY_SARIF',
    GRYPE_JSON = 'GRYPE_JSON',
    SNYK_JSON = 'SNYK_JSON',
    CUSTOM = 'CUSTOM',
}

export class NormalizeResultDto {
    @ApiProperty({
        description: 'Source format of the scan result',
        enum: NormalizationFormat,
        example: NormalizationFormat.TRIVY_JSON,
    })
    @IsEnum(NormalizationFormat)
    sourceFormat: NormalizationFormat;

    @ApiPropertyOptional({
        description: 'Schema version of the source format',
        example: '2',
    })
    @IsOptional()
    @IsString()
    schemaVersion?: string;

    @ApiPropertyOptional({
        description: 'Scanner version that produced the result',
        example: '0.48.0',
    })
    @IsOptional()
    @IsString()
    scannerVersion?: string;
}

export class NormalizedResultResponseDto {
    @ApiProperty({ description: 'Internal schema version' })
    schemaVersion: string;

    @ApiProperty({ description: 'Scanner information' })
    scanner: {
        name: string;
        version: string;
        originalSchemaVersion?: string;
    };

    @ApiProperty({ description: 'Artifact information' })
    artifact: {
        name: string;
        type: string;
        digest?: string;
    };

    @ApiProperty({ description: 'Scan metadata' })
    scanMetadata: {
        scannedAt: Date;
        duration?: number;
    };

    @ApiProperty({ description: 'Number of vulnerabilities' })
    vulnerabilityCount: number;

    @ApiProperty({ description: 'Summary by severity' })
    summary: {
        total: number;
        bySeverity: Record<string, number>;
        fixable: number;
    };
}
