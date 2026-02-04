// src/config/redis.ts
import Redis from 'ioredis';
import { logger } from '../core/utils/logger';
import { config } from '.';

export const initRedis = (): Redis => {
  const redis = new Redis({
    host: config.redisHost,
    port: config.redisPort,
    password: config.redisPassword,
    db: config.redisDb,
    retryStrategy: (times) => {
      const delay = Math.min(times * 50, 2000);
      return delay;
    },
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
  });

  redis.on('connect', () => {
    logger.info('Redis connected');
  });

  redis.on('error', (error) => {
    logger.error('Redis error:', error);
  });

  redis.on('reconnecting', () => {
    logger.info('Redis reconnecting...');
  });

  redis.on('close', () => {
    logger.warn('Redis connection closed');
  });

  return redis;
};