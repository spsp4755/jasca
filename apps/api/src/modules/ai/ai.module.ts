import { Module } from '@nestjs/common';
import { AiService } from './ai.service';
import { AiController } from './ai.controller';
import { AiExportService } from './ai-export.service';
import { PrismaModule } from '../../prisma/prisma.module';

@Module({
    imports: [PrismaModule],
    controllers: [AiController],
    providers: [AiService, AiExportService],
    exports: [AiService, AiExportService],
})
export class AiModule { }
