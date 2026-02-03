// src/core/middlewares/validation.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { ZodSchema } from 'zod';

export class ValidationMiddleware {
  // Validate request body with Zod schema
  validateBody = (schema: ZodSchema) => {
    return (req: Request, res: Response, next: NextFunction) => {
      try {
        const validated = schema.parse(req.body);
        req.body = validated;
        next();
      } catch (error: any) {
        return res.status(400).json({
          error: 'Validation failed',
          details: error.errors,
          code: 'VALIDATION_ERROR',
        });
      }
    };
  };

  // Validate query parameters
  validateQuery = (schema: ZodSchema) => {
    return (req: Request, res: Response, next: NextFunction) => {
      try {
        const validated = schema.parse(req.query);
        req.query = validated;
        next();
      } catch (error: any) {
        return res.status(400).json({
          error: 'Query validation failed',
          details: error.errors,
          code: 'QUERY_VALIDATION_ERROR',
        });
      }
    };
  };

  // Validate path parameters
  validateParams = (schema: ZodSchema) => {
    return (req: Request, res: Response, next: NextFunction) => {
      try {
        const validated = schema.parse(req.params);
        req.params = validated;
        next();
      } catch (error: any) {
        return res.status(400).json({
          error: 'Parameter validation failed',
          details: error.errors,
          code: 'PARAM_VALIDATION_ERROR',
        });
      }
    };
  };

  // File upload validation
  validateFile = (
    fieldName: string,
    allowedTypes: string[],
    maxSize: number
  ) => {
    return (req: Request, res: Response, next: NextFunction) => {
      const file = (req as any).files?.[fieldName];
      
      if (!file) {
        return next();
      }

      // Check file type
      if (!allowedTypes.includes(file.mimetype)) {
        return res.status(400).json({
          error: 'Invalid file type',
          allowed: allowedTypes,
          code: 'INVALID_FILE_TYPE',
        });
      }

      // Check file size
      if (file.size > maxSize) {
        return res.status(400).json({
          error: 'File too large',
          maxSize: `${maxSize / 1024 / 1024}MB`,
          code: 'FILE_TOO_LARGE',
        });
      }

      next();
    };
  };
}