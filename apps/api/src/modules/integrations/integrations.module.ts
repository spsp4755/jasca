import { Module } from '@nestjs/common';
import { DevOpsIntegrationService } from './devops-integration.service';
import { PrismaModule } from '../../prisma/prisma.module';

@Module({
    imports: [PrismaModule],
    providers: [DevOpsIntegrationService],
    exports: [DevOpsIntegrationService],
})
export class IntegrationsModule { }
