import { Module } from '@nestjs/common';
import { MultiOrgService } from './multi-org.service';
import { PrismaModule } from '../../prisma/prisma.module';

@Module({
    imports: [PrismaModule],
    providers: [MultiOrgService],
    exports: [MultiOrgService],
})
export class MultiOrgModule { }
