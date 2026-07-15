import { Module } from '@nestjs/common';
import { ScansModule } from '../scans/scans.module';
import { SettingsModule } from '../settings/settings.module';
import { HarborController, HarborWebhookController } from './harbor.controller';
import { HarborScanService } from './harbor-scan.service';
import { HarborService } from './harbor.service';

@Module({
    imports: [SettingsModule, ScansModule],
    controllers: [HarborController, HarborWebhookController],
    providers: [HarborService, HarborScanService],
    exports: [HarborService, HarborScanService],
})
export class HarborModule {}
