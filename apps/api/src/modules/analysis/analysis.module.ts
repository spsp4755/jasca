import { Module } from '@nestjs/common';
import { MitreAttackService } from './mitre-attack.service';
import { ZeroDayService } from './zero-day.service';
import { ThreatIntelService } from './threat-intel.service';
import { PrismaModule } from '../../prisma/prisma.module';

@Module({
    imports: [PrismaModule],
    providers: [MitreAttackService, ZeroDayService, ThreatIntelService],
    exports: [MitreAttackService, ZeroDayService, ThreatIntelService],
})
export class AnalysisModule { }
