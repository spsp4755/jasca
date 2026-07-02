import { Module } from '@nestjs/common';
import { PoliciesService } from './policies.service';
import { PoliciesController } from './policies.controller';
import { PolicyEngineService } from './policy-engine.service';
import { RiskScoreService } from './services/risk-score.service';
import { ConditionalPolicyService } from './services/conditional-policy.service';
import { PrismaModule } from '../../prisma/prisma.module';

@Module({
    imports: [PrismaModule],
    controllers: [PoliciesController],
    providers: [
        PoliciesService,
        PolicyEngineService,
        RiskScoreService,
        ConditionalPolicyService,
    ],
    exports: [
        PoliciesService,
        PolicyEngineService,
        RiskScoreService,
        ConditionalPolicyService,
    ],
})
export class PoliciesModule { }

