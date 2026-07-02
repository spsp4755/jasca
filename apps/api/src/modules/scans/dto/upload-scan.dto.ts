import { IsOptional, IsString, IsEnum } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { SourceType } from '@prisma/client';

export class UploadScanDto {
    @ApiProperty({
        enum: [
            'TRIVY_JSON',
            'TRIVY_SARIF',
            'CI_BAMBOO',
            'CI_GITLAB',
            'CI_JENKINS',
            'CI_GITHUB_ACTIONS',
            'MANUAL',
        ],
        default: 'TRIVY_JSON',
    })
    @IsEnum(SourceType)
    sourceType: SourceType;

    @ApiPropertyOptional({
        description: 'Project name - if projectId is not provided, will find or create a project with this name',
        example: 'my-app',
    })
    @IsString()
    @IsOptional()
    projectName?: string;

    @ApiPropertyOptional({
        description: 'Organization ID - required when auto-creating a new project',
        example: 'org-uuid-here',
    })
    @IsString()
    @IsOptional()
    organizationId?: string;

    @ApiPropertyOptional({ example: 'registry.example.com/app:v1.0.0' })
    @IsString()
    @IsOptional()
    imageRef?: string;

    @ApiPropertyOptional({ example: 'sha256:abc123...' })
    @IsString()
    @IsOptional()
    imageDigest?: string;

    @ApiPropertyOptional({ example: 'v1.0.0' })
    @IsString()
    @IsOptional()
    tag?: string;

    @ApiPropertyOptional({ example: 'abc1234567890' })
    @IsString()
    @IsOptional()
    commitHash?: string;

    @ApiPropertyOptional({ example: 'main' })
    @IsString()
    @IsOptional()
    branch?: string;

    @ApiPropertyOptional({ example: 'pipeline-123' })
    @IsString()
    @IsOptional()
    ciPipeline?: string;

    @ApiPropertyOptional({ example: 'https://ci.example.com/job/123' })
    @IsString()
    @IsOptional()
    ciJobUrl?: string;
}
