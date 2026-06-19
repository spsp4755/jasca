import { Module } from '@nestjs/common';
import { ManualAdvisoriesController } from './manual-advisories.controller';
import { ManualAdvisoriesService } from './manual-advisories.service';

@Module({
    controllers: [ManualAdvisoriesController],
    providers: [ManualAdvisoriesService],
    exports: [ManualAdvisoriesService],
})
export class ManualAdvisoriesModule { }
