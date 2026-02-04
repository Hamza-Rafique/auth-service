
import { Redis } from 'ioredis';
import { logger } from '../utils/logger';

export interface Metrics {
  requests: {
    total: number;
    byMethod: Record<string, number>;
    byStatus: Record<string, number>;
    byPath: Record<string, number>;
  };
  authentication: {
    logins: number;
    registrations: number;
    failures: number;
    passwordResets: number;
  };
  performance: {
    averageResponseTime: number;
    p95ResponseTime: number;
    p99ResponseTime: number;
    errorRate: number;
  };
  system: {
    memoryUsage: number;
    cpuUsage: number;
    uptime: number;
    activeConnections: number;
  };
}

export class MetricsService {
  private readonly redis: Redis;
  private readonly namespace = 'metrics';

  constructor(redis: Redis) {
    this.redis = redis;
  }

  // Track request
  async trackRequest(
    method: string,
    path: string,
    statusCode: number,
    duration: number
  ): Promise<void> {
    const timestamp = Math.floor(Date.now() / 1000);
    const minuteKey = `${this.namespace}:requests:minute:${Math.floor(timestamp / 60)}`;
    const hourKey = `${this.namespace}:requests:hour:${Math.floor(timestamp / 3600)}`;
    const dayKey = `${this.namespace}:requests:day:${Math.floor(timestamp / 86400)}`;

    const pipeline = this.redis.pipeline();
    
    // Increment totals
    pipeline.hincrby(`${this.namespace}:total`, 'requests', 1);
    pipeline.hincrby(`${this.namespace}:methods`, method, 1);
    pipeline.hincrby(`${this.namespace}:status`, String(statusCode), 1);
    pipeline.hincrby(`${this.namespace}:paths`, path, 1);
    
    // Time-based metrics
    pipeline.hincrby(minuteKey, 'count', 1);
    pipeline.hincrby(minuteKey, 'duration', duration);
    pipeline.expire(minuteKey, 120); // Keep for 2 minutes
    
    pipeline.hincrby(hourKey, 'count', 1);
    pipeline.hincrby(hourKey, 'duration', duration);
    pipeline.expire(hourKey, 7200); // Keep for 2 hours
    
    pipeline.hincrby(dayKey, 'count', 1);
    pipeline.hincrby(dayKey, 'duration', duration);
    pipeline.expire(dayKey, 172800); // Keep for 2 days
    
    await pipeline.exec();
  }

  // Track authentication event
  async trackAuthEvent(
    event: 'login' | 'registration' | 'login_failure' | 'password_reset',
    userId?: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    const key = `${this.namespace}:auth:${event}`;
    const timestamp = Date.now();
    
    const pipeline = this.redis.pipeline();
    
    pipeline.hincrby(key, 'count', 1);
    pipeline.zadd(`${key}:timeline`, timestamp, `${timestamp}:${userId || 'anonymous'}`);
    pipeline.zremrangebyscore(`${key}:timeline`, 0, timestamp - (24 * 60 * 60 * 1000)); // Keep 24h
    
    if (metadata) {
      pipeline.hmset(`${key}:${timestamp}`, metadata);
      pipeline.expire(`${key}:${timestamp}`, 86400); // 24 hours
    }
    
    await pipeline.exec();
  }

  // Track error
  async trackError(
    errorCode: string,
    context?: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    const key = `${this.namespace}:errors:${errorCode}`;
    
    const pipeline = this.redis.pipeline();
    pipeline.hincrby(key, 'count', 1);
    pipeline.hincrby(`${key}:context`, context || 'unknown', 1);
    
    if (metadata) {
      const errorKey = `${key}:${Date.now()}`;
      pipeline.hmset(errorKey, metadata);
      pipeline.expire(errorKey, 86400); // 24 hours
    }
    
    await pipeline.exec();
  }

  // Get metrics
  async getMetrics(timeframe: 'hour' | 'day' | 'week' = 'day'): Promise<Metrics> {
    const [requests, auth, performance] = await Promise.all([
      this.getRequestMetrics(timeframe),
      this.getAuthMetrics(timeframe),
      this.getPerformanceMetrics(timeframe)
    ]);

    return {
      requests,
      authentication: auth,
      performance,
      system: await this.getSystemMetrics()
    };
  }

  private async getRequestMetrics(timeframe: string) {
    const now = Math.floor(Date.now() / 1000);
    let startTime: number;
    
    switch (timeframe) {
      case 'hour':
        startTime = now - 3600;
        break;
      case 'week':
        startTime = now - 604800;
        break;
      default: // day
        startTime = now - 86400;
    }

    const [total, methods, status, paths] = await Promise.all([
      this.redis.hgetall(`${this.namespace}:total`),
      this.redis.hgetall(`${this.namespace}:methods`),
      this.redis.hgetall(`${this.namespace}:status`),
      this.redis.hgetall(`${this.namespace}:paths`)
    ]);

    return {
      total: parseInt(total.requests || '0'),
      byMethod: methods,
      byStatus: status,
      byPath: paths
    };
  }

  private async getAuthMetrics(timeframe: string) {
    const events = ['logins', 'registrations', 'failures', 'password_resets'];
    const result: Record<string, number> = {};

    for (const event of events) {
      const count = await this.redis.hget(`${this.namespace}:auth:${event}`, 'count');
      result[event] = parseInt(count || '0');
    }

    return {
      logins: result.logins || 0,
      registrations: result.registrations || 0,
      failures: result.failures || 0,
      passwordResets: result.password_resets || 0
    };
  }

  private async getPerformanceMetrics(timeframe: string) {
    // Calculate from stored minute/hour/day aggregates
    const now = Math.floor(Date.now() / 1000);
    const hourKey = `${this.namespace}:requests:hour:${Math.floor(now / 3600)}`;
    
    const [count, duration] = await Promise.all([
      this.redis.hget(hourKey, 'count'),
      this.redis.hget(hourKey, 'duration')
    ]);

    const totalRequests = parseInt(count || '0');
    const totalDuration = parseInt(duration || '0');
    
    return {
      averageResponseTime: totalRequests > 0 ? totalDuration / totalRequests : 0,
      p95ResponseTime: 0, // Would require more detailed tracking
      p99ResponseTime: 0,
      errorRate: 0 // Would require error tracking
    };
  }

  private async getSystemMetrics() {
    const memoryUsage = process.memoryUsage();
    const memoryPercentage = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;

    return {
      memoryUsage: Math.round(memoryPercentage * 100) / 100,
      cpuUsage: 0, // Would require CPU monitoring
      uptime: process.uptime(),
      activeConnections: 0 // Would require connection tracking
    };
  }

  // Reset metrics
  async resetMetrics(): Promise<void> {
    const keys = await this.redis.keys(`${this.namespace}:*`);
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
  }

  // Export metrics for monitoring systems
  async exportPrometheusMetrics(): Promise<string> {
    const metrics = await this.getMetrics('hour');
    
    let prometheus = '# HELP http_requests_total Total number of HTTP requests\n';
    prometheus += '# TYPE http_requests_total counter\n';
    prometheus += `http_requests_total ${metrics.requests.total}\n\n`;
    
    prometheus += '# HELP http_requests_by_method_total Total number of HTTP requests by method\n';
    prometheus += '# TYPE http_requests_by_method_total counter\n';
    Object.entries(metrics.requests.byMethod).forEach(([method, count]) => {
      prometheus += `http_requests_by_method_total{method="${method}"} ${count}\n`;
    });
    
    prometheus += '\n# HELP auth_logins_total Total number of logins\n';
    prometheus += '# TYPE auth_logins_total counter\n';
    prometheus += `auth_logins_total ${metrics.authentication.logins}\n`;
    
    prometheus += '\n# HELP system_memory_usage_percentage Memory usage percentage\n';
    prometheus += '# TYPE system_memory_usage_percentage gauge\n';
    prometheus += `system_memory_usage_percentage ${metrics.system.memoryUsage}\n`;
    
    return prometheus;
  }
}