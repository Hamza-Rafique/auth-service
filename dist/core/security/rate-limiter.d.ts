import { Redis } from 'ioredis';
export declare class RateLimiter {
    private redisClient;
    constructor(redisClient: Redis);
    get generalLimiter(): import("express-rate-limit").RateLimitRequestHandler;
    get authLimiter(): import("express-rate-limit").RateLimitRequestHandler;
    get passwordResetLimiter(): import("express-rate-limit").RateLimitRequestHandler;
    dynamicLimiter(maxRequests: number, windowMs: number): import("express-rate-limit").RateLimitRequestHandler;
}
//# sourceMappingURL=rate-limiter.d.ts.map