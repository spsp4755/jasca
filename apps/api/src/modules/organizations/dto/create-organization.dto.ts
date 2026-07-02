import { IsNotEmpty, IsString, IsOptional, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateOrganizationDto {
    @ApiProperty({ example: 'Acme Corporation' })
    @IsString()
    @IsNotEmpty()
    name: string;

    @ApiProperty({ example: 'acme-corp' })
    @IsString()
    @IsNotEmpty()
    @Matches(/^[a-z0-9-]+$/, {
        message: 'Slug must be lowercase alphanumeric with hyphens only',
    })
    slug: string;

    @ApiProperty({ example: 'Main organization for Acme', required: false })
    @IsString()
    @IsOptional()
    description?: string;
}
