// src/config/database.ts
import { PrismaClient } from '@prisma/client';
import { logger } from '../core/utils/logger';

export const initDatabase = (): PrismaClient => {
  const prisma = new PrismaClient({
    log: [
      { level: 'warn', emit: 'event' },
      { level: 'info', emit: 'event' },
      { level: 'error', emit: 'event' },
    ],
  });

  // Log database events
  prisma.$on('warn', (e) => {
    logger.warn('Prisma Warning:', e);
  });

  prisma.$on('info', (e) => {
    logger.info('Prisma Info:', e);
  });

  prisma.$on('error', (e) => {
    logger.error('Prisma Error:', e);
  });

  // Middleware for logging queries
  prisma.$use(async (params, next) => {
    const before = Date.now();
    const result = await next(params);
    const after = Date.now();
    
    logger.debug(`Query ${params.model}.${params.action} took ${after - before}ms`);
    
    return result;
  });

  return prisma;
};