import { PrismaClient } from '@prisma/client';
import { Redis } from 'ioredis';
import { logger } from '../utils/logger';

export interface HealthCheckResult {
  status: 'healthy' | 'unhealthy';
  timestamp: string;
  uptime: number;
  services: {
    database: {
      status: 'healthy' | 'unhealthy';
      latency?: number;
      error?: string;
    };
    redis: {
      status: 'healthy' | 'unhealthy';
      latency?: number;
      error?: string;
    };
    memory: {
      status: 'healthy' | 'unhealthy';
      usage: {
        rss: number;
        heapTotal: number;
        heapUsed: number;
        external: number;
      };
      percentage: number;
    };
  };
  version: string;
  environment: string;
}

export class HealthService {
  constructor(
    private prisma: PrismaClient,
    private redis: Redis
  ) {}

  async check(): Promise<HealthCheckResult> {
    const startTime = Date.now();
    const checks = await Promise.allSettled([
      this.checkDatabase(),
      this.checkRedis(),
      this.checkMemory()
    ]);

    const [dbResult, redisResult, memoryResult] = checks;

    const isHealthy = checks.every(
      check => check.status === 'fulfilled' && 
      (check as PromiseFulfilledResult<any>).value.status === 'healthy'
    );

    return {
      status: isHealthy ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      services: {
        database: dbResult.status === 'fulfilled' ? dbResult.value : {
          status: 'unhealthy',
          error: dbResult.status === 'rejected' ? dbResult.reason.message : 'Unknown error'
        },
        redis: redisResult.status === 'fulfilled' ? redisResult.value : {
          status: 'unhealthy',
          error: redisResult.status === 'rejected' ? redisResult.reason.message : 'Unknown error'
        },
        memory: memoryResult.status === 'fulfilled' ? memoryResult.value : {
          status: 'unhealthy',
          usage: { rss: 0, heapTotal: 0, heapUsed: 0, external: 0 },
          percentage: 0
        }
      },
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development'
    };
  }

  private async checkDatabase(): Promise<{
    status: 'healthy' | 'unhealthy';
    latency?: number;
    error?: string;
  }> {
    const start = Date.now();
    
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      const latency = Date.now() - start;
      
      return {
        status: 'healthy',
        latency
      };
    } catch (error: any) {
      logger.error({
        type: 'HEALTH_CHECK',
        service: 'database',
        error: error.message
      }, 'Database health check failed');
      
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }

  private async checkRedis(): Promise<{
    status: 'healthy' | 'unhealthy';
    latency?: number;
    error?: string;
  }> {
    const start = Date.now();
    
    try {
      await this.redis.ping();
      const latency = Date.now() - start;
      
      return {
        status: 'healthy',
        latency
      };
    } catch (error: any) {
      logger.error({
        type: 'HEALTH_CHECK',
        service: 'redis',
        error: error.message
      }, 'Redis health check failed');
      
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }

  private checkMemory(): {
    status: 'healthy' | 'unhealthy';
    usage: {
      rss: number;
      heapTotal: number;
      heapUsed: number;
      external: number;
    };
    percentage: number;
  } {
    const memoryUsage = process.memoryUsage();
    const memoryPercentage = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;
    
    const isHealthy = memoryPercentage < 90; // Alert if > 90% memory usage
    
    return {
      status: isHealthy ? 'healthy' : 'unhealthy',
      usage: {
        rss: Math.round(memoryUsage.rss / 1024 / 1024), // MB
        heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024), // MB
        heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024), // MB
        external: Math.round(memoryUsage.external / 1024 / 1024) // MB
      },
      percentage: Math.round(memoryPercentage * 100) / 100
    };
  }

  // Detailed health check with metrics
  async detailedCheck() {
    const basicHealth = await this.check();
    
    return {
      ...basicHealth,
      metrics: {
        responseTime: Date.now() - performance.now(),
        activeConnections: (process as any)._getActiveConnections?.() || 'N/A',
        loadAverage: process.cpuUsage(),
        eventLoopDelay: await this.getEventLoopDelay()
      },
      info: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        pid: process.pid,
        cwd: process.cwd()
      }
    };
  }

  private async getEventLoopDelay(): Promise<number> {
    return new Promise(resolve => {
      const start = process.hrtime.bigint();
      setImmediate(() => {
        const end = process.hrtime.bigint();
        const delay = Number(end - start) / 1e6; // Convert to ms
        resolve(delay);
      });
    });
  }
}