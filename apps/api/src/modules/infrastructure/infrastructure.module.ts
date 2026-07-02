import { Module, Global } from '@nestjs/common';
import { RateLimitService } from './rate-limit.service';
import { CacheService } from './cache.service';

@Global()
@Module({
    providers: [RateLimitService, CacheService],
    exports: [RateLimitService, CacheService],
})
export class InfrastructureModule { }
