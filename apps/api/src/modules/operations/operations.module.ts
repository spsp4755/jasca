import { Module } from '@nestjs/common';
import { OperationsService } from './operations.service';
import { PrismaModule } from '../../prisma/prisma.module';

@Module({
    imports: [PrismaModule],
    providers: [OperationsService],
    exports: [OperationsService],
})
export class OperationsModule { }
