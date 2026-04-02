import {
    Controller,
    Get,
    Put,
    Param,
    Body,
    UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Permissions } from '../../common/decorators/permissions.decorator';
import { SettingsService } from './settings.service';

@ApiTags('Settings')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('settings')
export class SettingsController {
    constructor(private readonly settingsService: SettingsService) { }

    @Get()
    @Permissions('settings:read')
    @ApiOperation({ summary: 'Get all settings' })
    async getAll() {
        return this.settingsService.getAll();
    }

    @Get(':key')
    @Permissions('settings:read')
    @ApiOperation({ summary: 'Get setting by key' })
    async get(@Param('key') key: string) {
        return this.settingsService.get(key);
    }

    @Put(':key')
    @Permissions('settings:update')
    @ApiOperation({ summary: 'Update setting' })
    async update(
        @Param('key') key: string,
        @Body() body: { value: unknown },
    ) {
        return this.settingsService.set(key, body.value);
    }
}
