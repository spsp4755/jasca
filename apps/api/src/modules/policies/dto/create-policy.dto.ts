import {
    IsString,
    IsOptional,
    IsBoolean,
    IsArray,
    ValidateNested,
    IsNumber,
    IsObject,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { PolicyRuleType, PolicyAction } from '@prisma/client';

export class CreatePolicyRuleDto {
    @ApiProperty({ enum: PolicyRuleType })
    @IsString()
    ruleType: PolicyRuleType | string;

    @ApiProperty({
        description: 'Conditions as JSON object',
        example: { severity: ['CRITICAL', 'HIGH'] },
    })
    @IsOptional()
    @IsObject()
    conditions: any;

    @ApiProperty({ enum: PolicyAction })
    @IsString()
    action: PolicyAction | string;

    @ApiPropertyOptional()
    @IsString()
    @IsOptional()
    message?: string;

    @ApiPropertyOptional({ description: 'Legacy UI operator, normalized by the service' })
    @IsString()
    @IsOptional()
    operator?: string;

    @ApiPropertyOptional({ description: 'Legacy UI value, normalized into conditions by the service' })
    @IsString()
    @IsOptional()
    value?: string;

    @ApiPropertyOptional({ description: 'Legacy single condition value' })
    @IsString()
    @IsOptional()
    condition?: string;

    @ApiPropertyOptional()
    @IsNumber()
    @IsOptional()
    priority?: number;

    @ApiPropertyOptional()
    @IsBoolean()
    @IsOptional()
    sendNotification?: boolean;
}

export class CreatePolicyDto {
    @ApiProperty({ example: 'Block Critical Vulnerabilities' })
    @IsString()
    name: string;

    @ApiPropertyOptional()
    @IsString()
    @IsOptional()
    description?: string;

    @ApiPropertyOptional()
    @IsBoolean()
    @IsOptional()
    isActive?: boolean;

    @ApiPropertyOptional()
    @IsString()
    @IsOptional()
    organizationId?: string;

    @ApiPropertyOptional()
    @IsString()
    @IsOptional()
    projectId?: string;

    @ApiPropertyOptional({ type: [CreatePolicyRuleDto] })
    @IsArray()
    @ValidateNested({ each: true })
    @Type(() => CreatePolicyRuleDto)
    @IsOptional()
    rules?: CreatePolicyRuleDto[];
}
