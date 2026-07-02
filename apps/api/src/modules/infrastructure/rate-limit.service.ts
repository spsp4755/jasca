import { Injectable, Logger, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

interface RateLimitEntry {
    count: number;
    resetAt: number;
}

export interface RateLimitConfig {
    windowMs: number;
    maxRequests: number;
    keyGenerator?: (req: Request) => string;
}

@Injectable()
export class RateLimitService {
    private readonly logger = new Logger(RateLimitService.name);

    // In-memory store (use Redis in production)
    private store: Map<string, RateLimitEntry> = new Map();

    private readonly defaultConfig: RateLimitConfig = {
        windowMs: 60 * 1000, // 1 minute
        maxRequests: 100,
    };

    /**
     * Check if request is rate limited
     */
    isRateLimited(key: string, config: RateLimitConfig = this.defaultConfig): {
        limited: boolean;
        remaining: number;
        resetAt: number;
    } {
        const now = Date.now();
        const entry = this.store.get(key);

        if (!entry || entry.resetAt <= now) {
            // Create new window
            const resetAt = now + config.windowMs;
            this.store.set(key, { count: 1, resetAt });
            return {
                limited: false,
                remaining: config.maxRequests - 1,
                resetAt,
            };
        }

        if (entry.count >= config.maxRequests) {
            return {
                limited: true,
                remaining: 0,
                resetAt: entry.resetAt,
            };
        }

        entry.count++;
        this.store.set(key, entry);

        return {
            limited: false,
            remaining: config.maxRequests - entry.count,
            resetAt: entry.resetAt,
        };
    }

    /**
     * Get rate limit configurations for different endpoints
     */
    getEndpointConfig(endpoint: string): RateLimitConfig {
        // Define different limits for different endpoints
        const configs: Record<string, RateLimitConfig> = {
            '/api/scans': { windowMs: 60000, maxRequests: 10 },
            '/api/auth/login': { windowMs: 300000, maxRequests: 5 },
            '/api/reports': { windowMs: 60000, maxRequests: 20 },
            default: this.defaultConfig,
        };

        return configs[endpoint] || configs.default;
    }

    /**
     * Create rate limit middleware
     */
    createMiddleware(config?: RateLimitConfig): NestMiddleware['use'] {
        const cfg = config || this.defaultConfig;

        return (req: Request, res: Response, next: NextFunction) => {
            const key = this.getKey(req);
            const result = this.isRateLimited(key, cfg);

            res.setHeader('X-RateLimit-Limit', cfg.maxRequests);
            res.setHeader('X-RateLimit-Remaining', result.remaining);
            res.setHeader('X-RateLimit-Reset', result.resetAt);

            if (result.limited) {
                res.status(429).json({
                    statusCode: 429,
                    message: 'Too many requests',
                    retryAfter: Math.ceil((result.resetAt - Date.now()) / 1000),
                });
                return;
            }

            next();
        };
    }

    /**
     * Clear rate limit entries (for testing/admin)
     */
    clearLimits(key?: string): void {
        if (key) {
            this.store.delete(key);
        } else {
            this.store.clear();
        }
    }

    /**
     * Get current rate limit status for a key
     */
    getStatus(key: string): RateLimitEntry | undefined {
        const entry = this.store.get(key);
        if (entry && entry.resetAt > Date.now()) {
            return entry;
        }
        return undefined;
    }

    // Helper to generate key from request
    private getKey(req: Request): string {
        const ip = req.ip || req.socket.remoteAddress || 'unknown';
        const userId = (req as any).user?.id;
        return userId ? `user:${userId}` : `ip:${ip}`;
    }
}
