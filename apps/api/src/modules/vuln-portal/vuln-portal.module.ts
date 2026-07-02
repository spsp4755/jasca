import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { SettingsModule } from '../settings/settings.module';
import { VulnPortalController } from './vuln-portal.controller';
import { VulnPortalService } from './vuln-portal.service';

@Module({
    imports: [PrismaModule, SettingsModule],
    controllers: [VulnPortalController],
    providers: [VulnPortalService],
    exports: [VulnPortalService],
})
export class VulnPortalModule { }
