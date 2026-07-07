import { Body, Controller, Delete, Get, Param, Post, Put, Query, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { SemgrepRulesService, SemgrepRuleDto } from './semgrep-rules.service';

@ApiTags('Semgrep Rules')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('SYSTEM_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN')
@Controller('semgrep-rules')
export class SemgrepRulesController {
    constructor(private readonly semgrepRulesService: SemgrepRulesService) { }

    @Get()
    @ApiOperation({ summary: 'List custom semgrep rules' })
    @ApiQuery({ name: 'isActive', required: false })
    async findAll(@Query('isActive') isActive?: string) {
        return this.semgrepRulesService.findAll(
            isActive === undefined ? undefined : isActive.toLowerCase() === 'true',
        );
    }

    @Post()
    @ApiOperation({ summary: 'Create a custom semgrep rule (YAML validated on save)' })
    async create(@Body() dto: SemgrepRuleDto, @CurrentUser() user?: any) {
        return this.semgrepRulesService.create(dto, user?.id);
    }

    @Post('validate')
    @ApiOperation({ summary: 'Validate rule YAML without saving' })
    async validate(@Body() dto: SemgrepRuleDto) {
        this.semgrepRulesService.validateDto({ name: dto.name || 'validation', yaml: dto.yaml });
        return { valid: true };
    }

    @Put(':id')
    @ApiOperation({ summary: 'Update a custom semgrep rule' })
    async update(@Param('id') id: string, @Body() dto: Partial<SemgrepRuleDto>) {
        return this.semgrepRulesService.update(id, dto);
    }

    @Delete(':id')
    @ApiOperation({ summary: 'Delete a custom semgrep rule' })
    async remove(@Param('id') id: string) {
        return this.semgrepRulesService.remove(id);
    }
}
