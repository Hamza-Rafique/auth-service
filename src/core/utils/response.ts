import { Response } from 'express';

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  meta?: {
    page?: number;
    limit?: number;
    total?: number;
    totalPages?: number;
    hasNext?: boolean;
    hasPrev?: boolean;
  };
  error?: string;
  code?: string;
}

export class ResponseHandler {
  // Success responses
  static success<T>(
    res: Response,
    data?: T,
    message: string = 'Success',
    statusCode: number = 200
  ) {
    const response: ApiResponse<T> = {
      success: true,
      message,
      data
    };

    return res.status(statusCode).json(response);
  }

  // Created response
  static created<T>(
    res: Response,
    data?: T,
    message: string = 'Resource created successfully'
  ) {
    return this.success(res, data, message, 201);
  }

  // Paginated response
  static paginated<T>(
    res: Response,
    data: T[],
    meta: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
    },
    message: string = 'Data retrieved successfully'
  ) {
    const response: ApiResponse<T[]> = {
      success: true,
      message,
      data,
      meta: {
        ...meta,
        hasNext: meta.page < meta.totalPages,
        hasPrev: meta.page > 1
      }
    };

    return res.status(200).json(response);
  }

  // No content response
  static noContent(res: Response, message: string = 'No content') {
    return res.status(204).json({
      success: true,
      message
    });
  }

  // Error responses
  static error(
    res: Response,
    error: string,
    code: string = 'INTERNAL_ERROR',
    statusCode: number = 500,
    details?: any
  ) {
    const response: ApiResponse = {
      success: false,
      error,
      code,
      ...(details && { details })
    };

    return res.status(statusCode).json(response);
  }

  // Bad request
  static badRequest(
    res: Response,
    error: string = 'Bad request',
    details?: any
  ) {
    return this.error(res, error, 'BAD_REQUEST', 400, details);
  }

  // Unauthorized
  static unauthorized(
    res: Response,
    error: string = 'Unauthorized'
  ) {
    return this.error(res, error, 'UNAUTHORIZED', 401);
  }

  // Forbidden
  static forbidden(
    res: Response,
    error: string = 'Forbidden'
  ) {
    return this.error(res, error, 'FORBIDDEN', 403);
  }

  // Not found
  static notFound(
    res: Response,
    error: string = 'Resource not found'
  ) {
    return this.error(res, error, 'NOT_FOUND', 404);
  }

  // Conflict
  static conflict(
    res: Response,
    error: string = 'Resource already exists'
  ) {
    return this.error(res, error, 'CONFLICT', 409);
  }

  // Too many requests
  static tooManyRequests(
    res: Response,
    error: string = 'Too many requests'
  ) {
    return this.error(res, error, 'TOO_MANY_REQUESTS', 429);
  }

  // Validation error
  static validationError(
    res: Response,
    error: string = 'Validation failed',
    details?: any
  ) {
    return this.error(res, error, 'VALIDATION_ERROR', 400, details);
  }

  // Internal server error
  static internalError(
    res: Response,
    error: string = 'Internal server error'
  ) {
    return this.error(res, error, 'INTERNAL_SERVER_ERROR', 500);
  }
}