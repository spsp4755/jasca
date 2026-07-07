import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { SemgrepRulesService } from './semgrep-rules.service';
import { SemgrepRulesController } from './semgrep-rules.controller';

@Module({
    imports: [PrismaModule],
    controllers: [SemgrepRulesController],
    providers: [SemgrepRulesService],
    exports: [SemgrepRulesService],
})
export class SemgrepRulesModule { }
