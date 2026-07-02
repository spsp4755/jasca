import { Module } from '@nestjs/common';
import { NormalizationEngineService } from './normalization-engine.service';
import { NormalizationController } from './normalization.controller';
import { SchemaVersionService } from './schema-version.service';
import { PrismaModule } from '../../prisma/prisma.module';

@Module({
    imports: [PrismaModule],
    controllers: [NormalizationController],
    providers: [NormalizationEngineService, SchemaVersionService],
    exports: [NormalizationEngineService, SchemaVersionService],
})
export class NormalizationModule { }
