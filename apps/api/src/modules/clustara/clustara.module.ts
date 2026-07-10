import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { SettingsModule } from '../settings/settings.module';
import { ClustaraController } from './clustara.controller';
import { ClustaraService } from './clustara.service';

@Module({
    imports: [PrismaModule, SettingsModule],
    controllers: [ClustaraController],
    providers: [ClustaraService],
    exports: [ClustaraService],
})
export class ClustaraModule { }
