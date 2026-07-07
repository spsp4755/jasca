import { Module } from '@nestjs/common';
import { MitreAttackService } from './mitre-attack.service';
import { ZeroDayService } from './zero-day.service';
import { ThreatIntelService } from './threat-intel.service';
import { ComplianceService } from './compliance.service';
import { PrismaModule } from '../../prisma/prisma.module';

@Module({
    imports: [PrismaModule],
    providers: [MitreAttackService, ZeroDayService, ThreatIntelService, ComplianceService],
    exports: [MitreAttackService, ZeroDayService, ThreatIntelService, ComplianceService],
})
export class AnalysisModule { }
