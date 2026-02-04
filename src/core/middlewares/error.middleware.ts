import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

export interface AppError extends Error {
  statusCode?: number;
  code?: string;
  details?: any;
  isOperational?: boolean;
}

export class AppError extends Error {
  constructor(
    message: string,
    statusCode: number = 500,
    code?: string,
    details?: any
  ) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

// Common error types
export const Errors = {
  // Authentication errors
  Unauthorized: (message: string = 'Unauthorized') => 
    new AppError(message, 401, 'UNAUTHORIZED'),
  
  Forbidden: (message: string = 'Forbidden') => 
    new AppError(message, 403, 'FORBIDDEN'),
  
  NotFound: (message: string = 'Resource not found') => 
    new AppError(message, 404, 'NOT_FOUND'),
  
  // Validation errors
  ValidationError: (message: string = 'Validation failed', details?: any) => 
    new AppError(message, 400, 'VALIDATION_ERROR', details),
  
  // Business logic errors
  Conflict: (message: string = 'Resource already exists') => 
    new AppError(message, 409, 'CONFLICT'),
  
  TooManyRequests: (message: string = 'Too many requests') => 
    new AppError(message, 429, 'TOO_MANY_REQUESTS'),
  
  // Server errors
  InternalServerError: (message: string = 'Internal server error') => 
    new AppError(message, 500, 'INTERNAL_SERVER_ERROR'),
  
  ServiceUnavailable: (message: string = 'Service unavailable') => 
    new AppError(message, 503, 'SERVICE_UNAVAILABLE')
};

// Error handling middleware
export const errorHandler = (
  error: AppError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Log the error
  logger.error({
    error: {
      name: error.name,
      message: error.message,
      stack: error.stack,
      code: error.code,
      details: error.details
    },
    request: {
      method: req.method,
      url: req.url,
      params: req.params,
      query: req.query,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    },
    user: (req as any).user?.id || 'anonymous'
  }, 'Error occurred');

  // Determine status code
  const statusCode = error.statusCode || 500;
  
  // Determine if error is operational
  const isOperational = error.isOperational || false;

  // Development vs production error response
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  const response: any = {
    success: false,
    error: error.message,
    code: error.code || 'INTERNAL_ERROR',
    ...(error.details && { details: error.details })
  };

  // Add stack trace in development
  if (isDevelopment && !isOperational) {
    response.stack = error.stack;
  }

  // Handle specific error types
  if (error.name === 'ValidationError') {
    response.code = 'VALIDATION_ERROR';
    response.details = error.details || {};
  }

  if (error.name === 'JsonWebTokenError') {
    response.code = 'INVALID_TOKEN';
    response.error = 'Invalid token';
  }

  if (error.name === 'TokenExpiredError') {
    response.code = 'TOKEN_EXPIRED';
    response.error = 'Token expired';
  }

  // Send response
  res.status(statusCode).json(response);
};

// Async error wrapper for controllers
export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// 404 handler
export const notFoundHandler = (req: Request, res: Response) => {
  throw Errors.NotFound(`Route ${req.method} ${req.originalUrl} not found`);
};

// Global unhandled rejection handler
process.on('unhandledRejection', (reason: Error | any, promise: Promise<any>) => {
  logger.error({
    type: 'UNHANDLED_REJECTION',
    reason: reason?.message || reason,
    stack: reason?.stack
  }, 'Unhandled Rejection at:', promise);
  
  // In production, you might want to gracefully shutdown
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
});

// Global uncaught exception handler
process.on('uncaughtException', (error: Error) => {
  logger.error({
    type: 'UNCAUGHT_EXCEPTION',
    error: error.message,
    stack: error.stack
  }, 'Uncaught Exception');
  
  // In production, you might want to gracefully shutdown
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
});