import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { Redis } from 'ioredis';
import { Request, Response } from 'express';

export class RateLimiter {
  private redisClient: Redis;

  constructor(redisClient: Redis) {
    this.redisClient = redisClient;
  }

  // General API rate limiter
  get generalLimiter() {
    return rateLimit({
      store: new RedisStore({
        client: this.redisClient,
        prefix: 'ratelimit:general:',
      }),
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // Limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later.',
      standardHeaders: true,
      legacyHeaders: false,
    });
  }

  // Stricter auth limiter
  get authLimiter() {
    return rateLimit({
      store: new RedisStore({
        client: this.redisClient,
        prefix: 'ratelimit:auth:',
      }),
      windowMs: 15 * 60 * 1000,
      max: 5, // Only 5 attempts per window for auth endpoints
      message: 'Too many login attempts, please try again later.',
      skipSuccessfulRequests: true, // Don't count successful requests
    });
  }

  // Password reset limiter
  get passwordResetLimiter() {
    return rateLimit({
      store: new RedisStore({
        client: this.redisClient,
        prefix: 'ratelimit:password-reset:',
      }),
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 3, // Only 3 password reset attempts per hour
      message: 'Too many password reset attempts, please try again later.',
    });
  }

  // Dynamic rate limiter based on user role
  dynamicLimiter(maxRequests: number, windowMs: number) {
    return rateLimit({
      store: new RedisStore({
        client: this.redisClient,
        prefix: 'ratelimit:dynamic:',
      }),
      windowMs,
      max: maxRequests,
      keyGenerator: (req: Request) => {
        // Use user ID if authenticated, otherwise IP
        return (req as any).user?.id || req.ip;
      },
    });
  }
}