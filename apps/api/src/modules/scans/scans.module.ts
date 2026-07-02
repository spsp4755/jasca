import { Module } from '@nestjs/common';
import { ScansService } from './scans.service';
import { ScansController } from './scans.controller';
import { TrivyParserService } from './services/trivy-parser.service';
import { VulnSyncService } from './services/vuln-sync.service';
import { TrivyScanService } from './services/trivy-scan.service';
import { LicensesModule } from '../licenses/licenses.module';
import { PoliciesModule } from '../policies/policies.module';
import { SettingsModule } from '../settings/settings.module';
import { ManualAdvisoriesModule } from '../manual-advisories/manual-advisories.module';
import { NotificationsModule } from '../notifications/notifications.module';

@Module({
    imports: [LicensesModule, PoliciesModule, SettingsModule, ManualAdvisoriesModule, NotificationsModule],
    controllers: [ScansController],
    providers: [ScansService, TrivyParserService, VulnSyncService, TrivyScanService],
    exports: [ScansService],
})
export class ScansModule { }

