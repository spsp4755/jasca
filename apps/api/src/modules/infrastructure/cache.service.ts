import { Injectable, Logger } from '@nestjs/common';

interface CacheEntry<T> {
    value: T;
    expiresAt: number;
}

export interface CacheConfig {
    ttlMs: number;
    maxSize?: number;
}

@Injectable()
export class CacheService {
    private readonly logger = new Logger(CacheService.name);

    // In-memory cache (use Redis in production)
    private cache: Map<string, CacheEntry<unknown>> = new Map();

    private readonly defaultTtl = 5 * 60 * 1000; // 5 minutes
    private readonly maxSize = 1000;

    /**
     * Get value from cache
     */
    get<T>(key: string): T | undefined {
        const entry = this.cache.get(key);

        if (!entry) {
            return undefined;
        }

        if (entry.expiresAt <= Date.now()) {
            this.cache.delete(key);
            return undefined;
        }

        return entry.value as T;
    }

    /**
     * Set value in cache
     */
    set<T>(key: string, value: T, ttlMs?: number): void {
        // Evict if at max size
        if (this.cache.size >= this.maxSize) {
            this.evictExpired();
            if (this.cache.size >= this.maxSize) {
                // Remove oldest entry
                const firstKey = this.cache.keys().next().value;
                if (firstKey) this.cache.delete(firstKey);
            }
        }

        this.cache.set(key, {
            value,
            expiresAt: Date.now() + (ttlMs || this.defaultTtl),
        });
    }

    /**
     * Get or set value (cache aside pattern)
     */
    async getOrSet<T>(
        key: string,
        factory: () => Promise<T>,
        ttlMs?: number,
    ): Promise<T> {
        const cached = this.get<T>(key);
        if (cached !== undefined) {
            return cached;
        }

        const value = await factory();
        this.set(key, value, ttlMs);
        return value;
    }

    /**
     * Delete value from cache
     */
    delete(key: string): boolean {
        return this.cache.delete(key);
    }

    /**
     * Delete by pattern (prefix)
     */
    deleteByPrefix(prefix: string): number {
        let count = 0;
        for (const key of this.cache.keys()) {
            if (key.startsWith(prefix)) {
                this.cache.delete(key);
                count++;
            }
        }
        return count;
    }

    /**
     * Clear all cache
     */
    clear(): void {
        this.cache.clear();
    }

    /**
     * Get cache stats
     */
    getStats(): {
        size: number;
        maxSize: number;
        hitRate: number;
    } {
        return {
            size: this.cache.size,
            maxSize: this.maxSize,
            hitRate: 0, // Would track hits/misses in production
        };
    }

    /**
     * Cache key generators for common patterns
     */
    static keys = {
        vulnerability: (cveId: string) => `vuln:${cveId}`,
        projectVulns: (projectId: string) => `project:${projectId}:vulns`,
        scanResult: (scanId: string) => `scan:${scanId}`,
        orgStats: (orgId: string) => `org:${orgId}:stats`,
        userBookmarks: (userId: string) => `user:${userId}:bookmarks`,
    };

    // Helper

    private evictExpired(): void {
        const now = Date.now();
        for (const [key, entry] of this.cache.entries()) {
            if (entry.expiresAt <= now) {
                this.cache.delete(key);
            }
        }
    }
}
