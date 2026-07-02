import { Module } from '@nestjs/common';
import { AutomationService } from './automation.service';
import { PrismaModule } from '../../prisma/prisma.module';

@Module({
    imports: [PrismaModule],
    providers: [AutomationService],
    exports: [AutomationService],
})
export class AutomationModule { }
