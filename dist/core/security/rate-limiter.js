"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RateLimiter = void 0;
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const rate_limit_redis_1 = __importDefault(require("rate-limit-redis"));
class RateLimiter {
    redisClient;
    constructor(redisClient) {
        this.redisClient = redisClient;
    }
    get generalLimiter() {
        return (0, express_rate_limit_1.default)({
            store: new rate_limit_redis_1.default({
                client: this.redisClient,
                prefix: 'ratelimit:general:',
            }),
            windowMs: 15 * 60 * 1000,
            max: 100,
            message: 'Too many requests from this IP, please try again later.',
            standardHeaders: true,
            legacyHeaders: false,
        });
    }
    get authLimiter() {
        return (0, express_rate_limit_1.default)({
            store: new rate_limit_redis_1.default({
                client: this.redisClient,
                prefix: 'ratelimit:auth:',
            }),
            windowMs: 15 * 60 * 1000,
            max: 5,
            message: 'Too many login attempts, please try again later.',
            skipSuccessfulRequests: true,
        });
    }
    get passwordResetLimiter() {
        return (0, express_rate_limit_1.default)({
            store: new rate_limit_redis_1.default({
                client: this.redisClient,
                prefix: 'ratelimit:password-reset:',
            }),
            windowMs: 60 * 60 * 1000,
            max: 3,
            message: 'Too many password reset attempts, please try again later.',
        });
    }
    dynamicLimiter(maxRequests, windowMs) {
        return (0, express_rate_limit_1.default)({
            store: new rate_limit_redis_1.default({
                client: this.redisClient,
                prefix: 'ratelimit:dynamic:',
            }),
            windowMs,
            max: maxRequests,
            keyGenerator: (req) => {
                return req.user?.id || req.ip;
            },
        });
    }
}
exports.RateLimiter = RateLimiter;
//# sourceMappingURL=rate-limiter.js.map