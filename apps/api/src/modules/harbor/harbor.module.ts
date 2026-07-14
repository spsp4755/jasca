import { Module } from '@nestjs/common';
import { SettingsModule } from '../settings/settings.module';
import { HarborController } from './harbor.controller';
import { HarborService } from './harbor.service';

@Module({
    imports: [SettingsModule],
    controllers: [HarborController],
    providers: [HarborService],
    exports: [HarborService],
})
export class HarborModule {}
