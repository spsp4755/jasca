import { BadRequestException, Body, Controller, Delete, Get, Param, Post, Put, Query, UploadedFile, UseGuards, UseInterceptors } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { FileInterceptor } from '@nestjs/platform-express';
import { Severity } from '@prisma/client';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { ManualAdvisoriesService, ManualAdvisoryDto } from './manual-advisories.service';

function parseBoolean(value?: string): boolean | undefined {
    if (value === undefined) return undefined;
    return value.toLowerCase() === 'true';
}

@ApiTags('Manual Advisories')
@ApiBearerAuth()
@ApiSecurity('api-key')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('SYSTEM_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN')
@Controller('manual-advisories')
export class ManualAdvisoriesController {
    constructor(private readonly manualAdvisoriesService: ManualAdvisoriesService) { }

    @Get()
    @ApiOperation({ summary: 'List manual vulnerability advisories' })
    @ApiQuery({ name: 'organizationId', required: false })
    @ApiQuery({ name: 'projectId', required: false })
    @ApiQuery({ name: 'isActive', required: false })
    async findAll(
        @CurrentUser() user: any,
        @Query('organizationId') organizationId?: string,
        @Query('projectId') projectId?: string,
        @Query('isActive') isActive?: string,
    ) {
        return this.manualAdvisoriesService.findAll(user, {
            organizationId,
            projectId,
            isActive: parseBoolean(isActive),
        });
    }

    @Post()
    @ApiOperation({ summary: 'Create a manual vulnerability advisory' })
    async create(@Body() dto: ManualAdvisoryDto, @CurrentUser() user: any) {
        return this.manualAdvisoriesService.create(this.normalizeDto(dto), user);
    }

    @Post('bulk')
    @ApiOperation({ summary: 'Bulk upsert manual vulnerability advisories from JSON' })
    async bulkUpsert(@Body() body: { items?: ManualAdvisoryDto[] } | ManualAdvisoryDto[], @CurrentUser() user: any) {
        const items = Array.isArray(body) ? body : body.items;
        if (!Array.isArray(items)) {
            throw new BadRequestException('Request body must be an array or { items: [...] }');
        }
        return this.manualAdvisoriesService.bulkUpsert(items.map((item) => this.normalizeDto(item)), user);
    }

    @Post('upload')
    @UseInterceptors(FileInterceptor('file', { limits: { fileSize: 1024 * 1024 } }))
    @ApiOperation({ summary: 'Bulk upsert manual vulnerability advisories from CSV or JSON file' })
    async upload(@UploadedFile() file: Express.Multer.File, @CurrentUser() user: any) {
        if (!file) {
            throw new BadRequestException('file is required');
        }

        const content = file.buffer.toString('utf8').replace(/^\uFEFF/, '');
        const filename = file.originalname.toLowerCase();
        const items = filename.endsWith('.json')
            ? this.parseJsonFile(content)
            : this.parseCsvFile(content);

        return this.manualAdvisoriesService.bulkUpsert(items.map((item) => this.normalizeDto(item)), user);
    }

    @Put(':id')
    @ApiOperation({ summary: 'Update a manual vulnerability advisory' })
    async update(
        @Param('id') id: string,
        @Body() dto: Partial<ManualAdvisoryDto>,
        @CurrentUser() user: any,
    ) {
        return this.manualAdvisoriesService.update(id, this.normalizeDto(dto), user);
    }

    @Delete(':id')
    @ApiOperation({ summary: 'Delete a manual vulnerability advisory' })
    async remove(@Param('id') id: string, @CurrentUser() user: any) {
        return this.manualAdvisoriesService.remove(id, user);
    }

    private normalizeDto<T extends Partial<ManualAdvisoryDto>>(dto: T): T {
        const rawReferences = (dto as any).references;
        return {
            ...dto,
            severity: dto.severity ? String(dto.severity).toUpperCase() as Severity : dto.severity,
            references: Array.isArray(rawReferences)
                ? rawReferences
                : typeof rawReferences === 'string'
                    ? String(rawReferences).split(/\r?\n/)
                    : rawReferences,
        };
    }

    private parseJsonFile(content: string): ManualAdvisoryDto[] {
        try {
            const parsed = JSON.parse(content);
            const items = Array.isArray(parsed) ? parsed : parsed.items;
            if (!Array.isArray(items)) {
                throw new BadRequestException('JSON file must be an array or { "items": [...] }');
            }
            return items;
        } catch (error) {
            if (error instanceof BadRequestException) throw error;
            throw new BadRequestException('Invalid JSON file');
        }
    }

    private parseCsvFile(content: string): ManualAdvisoryDto[] {
        const rows = this.parseCsvRows(content).filter((row) => row.some((cell) => cell.trim()));
        if (rows.length < 2) {
            throw new BadRequestException('CSV file must include a header row and at least one data row');
        }

        const headers = rows[0].map((header) => header.trim());
        return rows.slice(1).map((row) => {
            const item: Record<string, any> = {};
            headers.forEach((header, index) => {
                item[header] = row[index]?.trim() || undefined;
            });
            if (typeof item.references === 'string') {
                item.references = item.references.split(/[;\n]/).map((value: string) => value.trim()).filter(Boolean);
            }
            if (typeof item.isActive === 'string') {
                item.isActive = item.isActive.toLowerCase() !== 'false';
            }
            return item as ManualAdvisoryDto;
        });
    }

    private parseCsvRows(content: string): string[][] {
        const rows: string[][] = [];
        let row: string[] = [];
        let cell = '';
        let inQuotes = false;

        for (let index = 0; index < content.length; index++) {
            const char = content[index];
            const next = content[index + 1];

            if (char === '"' && inQuotes && next === '"') {
                cell += '"';
                index++;
            } else if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                row.push(cell);
                cell = '';
            } else if ((char === '\n' || char === '\r') && !inQuotes) {
                if (char === '\r' && next === '\n') index++;
                row.push(cell);
                rows.push(row);
                row = [];
                cell = '';
            } else {
                cell += char;
            }
        }

        row.push(cell);
        rows.push(row);
        return rows;
    }
}
