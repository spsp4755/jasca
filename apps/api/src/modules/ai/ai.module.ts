import { Module } from '@nestjs/common';
import { AiService } from './ai.service';
import { AiController } from './ai.controller';
import { AiExportService } from './ai-export.service';
import { AiJobService } from './ai-job.service';
import { PrismaModule } from '../../prisma/prisma.module';
import { NotificationsModule } from '../notifications/notifications.module';

@Module({
    imports: [PrismaModule, NotificationsModule],
    controllers: [AiController],
    providers: [AiService, AiExportService, AiJobService],
    exports: [AiService, AiExportService, AiJobService],
})
export class AiModule { }
