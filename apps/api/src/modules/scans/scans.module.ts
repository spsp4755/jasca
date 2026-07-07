import { Module } from '@nestjs/common';
import { ScansService } from './scans.service';
import { ScansController } from './scans.controller';
import { TrivyParserService } from './services/trivy-parser.service';
import { CheckovParserService } from './services/checkov-parser.service';
import { ZapParserService } from './services/zap-parser.service';
import { SarifParserService } from './services/sarif-parser.service';
import { VulnSyncService } from './services/vuln-sync.service';
import { TrivyScanService } from './services/trivy-scan.service';
import { CheckovScanService } from './services/checkov-scan.service';
import { ZapPolicyService } from './services/zap-policy.service';
import { ZapClientService } from './services/zap-client.service';
import { ZapScanService } from './services/zap-scan.service';
import { SemgrepScanService } from './services/semgrep-scan.service';
import { LicensesModule } from '../licenses/licenses.module';
import { PoliciesModule } from '../policies/policies.module';
import { SettingsModule } from '../settings/settings.module';
import { ManualAdvisoriesModule } from '../manual-advisories/manual-advisories.module';
import { NotificationsModule } from '../notifications/notifications.module';

@Module({
    imports: [LicensesModule, PoliciesModule, SettingsModule, ManualAdvisoriesModule, NotificationsModule],
    controllers: [ScansController],
    providers: [
        ScansService,
        TrivyParserService,
        CheckovParserService,
        ZapParserService,
        SarifParserService,
        VulnSyncService,
        TrivyScanService,
        CheckovScanService,
        ZapPolicyService,
        ZapClientService,
        ZapScanService,
        SemgrepScanService,
    ],
    exports: [ScansService],
})
export class ScansModule { }

