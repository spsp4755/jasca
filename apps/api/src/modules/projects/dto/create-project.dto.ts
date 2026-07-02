import { IsNotEmpty, IsString, IsOptional, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateProjectDto {
    @ApiProperty({ example: 'Backend API' })
    @IsString()
    @IsNotEmpty()
    name: string;

    @ApiProperty({ example: 'backend-api' })
    @IsString()
    @IsNotEmpty()
    @Matches(/^[a-z0-9-]+$/, {
        message: 'Slug must be lowercase alphanumeric with hyphens only',
    })
    slug: string;

    @ApiProperty({ example: 'Main backend service', required: false })
    @IsString()
    @IsOptional()
    description?: string;
}
