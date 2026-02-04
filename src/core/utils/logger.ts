import pino from 'pino';
import path from 'path';
import fs from 'fs';

const logLevel = process.env.LOG_LEVEL || 'info';

// Create logs directory if it doesn't exist
const logDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// Define log streams
const streams = [
  // File stream for all logs
  { 
    stream: fs.createWriteStream(
      path.join(logDir, 'app.log'), 
      { flags: 'a' }
    ) 
  },
  // Error-only file stream
  { 
    level: 'error' as pino.Level,
    stream: fs.createWriteStream(
      path.join(logDir, 'error.log'), 
      { flags: 'a' }
    ) 
  }
];

// Development pretty console
if (process.env.NODE_ENV === 'development') {
  streams.push({
    stream: process.stdout
  });
}

export const logger = pino({
  level: logLevel,
  transport: process.env.NODE_ENV === 'development' ? {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'SYS:standard',
      ignore: 'pid,hostname',
      destination: 1 // stdout
    }
  } : undefined,
  formatters: {
    level: (label) => {
      return { level: label.toUpperCase() };
    },
    bindings: (bindings) => {
      return {
        pid: bindings.pid,
        hostname: bindings.hostname,
        node_version: process.version
      };
    }
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  serializers: {
    req: (req) => {
      return {
        id: req.id,
        method: req.method,
        url: req.url,
        query: req.query,
        params: req.params,
        headers: {
          'user-agent': req.headers['user-agent'],
          'content-type': req.headers['content-type'],
          'authorization': req.headers['authorization'] ? '[REDACTED]' : undefined
        },
        remoteAddress: req.remoteAddress,
        remotePort: req.remotePort
      };
    },
    res: (res) => {
      return {
        statusCode: res.statusCode,
        headers: {
          'content-type': res.headers['content-type'],
          'content-length': res.headers['content-length']
        }
      };
    },
    err: pino.stdSerializers.err,
    error: pino.stdSerializers.err
  },
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'res.headers["set-cookie"]',
      'password',
      '*.password',
      'token',
      '*.token',
      'secret',
      '*.secret',
      'apiKey',
      '*.apiKey'
    ],
    censor: '[REDACTED]'
  }
}, pino.multistream(streams));

// Custom logger methods
export class LoggerService {
  // Structured logging for authentication events
  static authLog(
    event: string,
    userId?: string,
    metadata?: Record<string, any>
  ) {
    logger.info({
      type: 'AUTH',
      event,
      userId,
      ...metadata
    }, `Auth Event: ${event}`);
  }

  // Security event logging
  static securityLog(
    event: string,
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    metadata?: Record<string, any>
  ) {
    logger[severity === 'CRITICAL' || severity === 'HIGH' ? 'error' : 'warn']({
      type: 'SECURITY',
      event,
      severity,
      ...metadata
    }, `Security Event: ${event}`);
  }

  // Database operation logging
  static dbLog(
    operation: string,
    model: string,
    duration: number,
    metadata?: Record<string, any>
  ) {
    logger.debug({
      type: 'DATABASE',
      operation,
      model,
      duration,
      ...metadata
    }, `DB ${operation} on ${model} took ${duration}ms`);
  }

  // Request performance logging
  static performanceLog(
    method: string,
    path: string,
    duration: number,
    statusCode: number
  ) {
    const level = duration > 1000 ? 'warn' : 'info';
    
    logger[level]({
      type: 'PERFORMANCE',
      method,
      path,
      duration,
      statusCode
    }, `Request ${method} ${path} completed in ${duration}ms`);
  }

  // Business event logging
  static businessLog(
    event: string,
    entityType: string,
    entityId: string,
    userId?: string,
    metadata?: Record<string, any>
  ) {
    logger.info({
      type: 'BUSINESS',
      event,
      entityType,
      entityId,
      userId,
      ...metadata
    }, `Business Event: ${event} on ${entityType}:${entityId}`);
  }

  // Audit logging
  static auditLog(
    action: string,
    userId: string,
    resource: string,
    resourceId: string,
    changes?: Record<string, any>,
    ip?: string,
    userAgent?: string
  ) {
    logger.info({
      type: 'AUDIT',
      action,
      userId,
      resource,
      resourceId,
      changes,
      ip,
      userAgent,
      timestamp: new Date().toISOString()
    }, `Audit: ${action} on ${resource}:${resourceId} by ${userId}`);
  }

  // Error logging with context
  static errorLog(
    error: Error,
    context?: string,
    metadata?: Record<string, any>
  ) {
    logger.error({
      type: 'ERROR',
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack
      },
      context,
      ...metadata
    }, `Error in ${context}: ${error.message}`);
  }
}

// Middleware for request logging
export const requestLogger = () => {
  return pino.http({
    logger,
    serializers: {
      req: pino.stdSerializers.req,
      res: pino.stdSerializers.res,
      err: pino.stdSerializers.err
    },
    customSuccessMessage: (req, res) => {
      return `${req.method} ${req.url} ${res.statusCode}`;
    },
    customErrorMessage: (req, res, err) => {
      return `${req.method} ${req.url} ${res.statusCode} - ${err.message}`;
    },
    customAttributeKeys: {
      req: 'request',
      res: 'response',
      err: 'error',
      responseTime: 'duration'
    },
    wrapSerializers: false
  });
};