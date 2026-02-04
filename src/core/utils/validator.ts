// src/core/utils/validator.ts
import { z } from 'zod';
import { logger } from './logger';

export class Validator {
  // Common validation schemas
  static readonly email = z
    .string()
    .email('Invalid email format')
    .min(5, 'Email too short')
    .max(255, 'Email too long')
    .transform(email => email.toLowerCase().trim());

  static readonly password = z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(100, 'Password too long')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      'Password must contain uppercase, lowercase, number, and special character'
    );

  static readonly phone = z
    .string()
    .regex(/^\+?[\d\s\-\(\)]+$/, 'Invalid phone number')
    .optional();

  static readonly uuid = z
    .string()
    .uuid('Invalid UUID format');

  static readonly url = z
    .string()
    .url('Invalid URL format')
    .optional();

  // Pagination schema
  static readonly pagination = z.object({
    page: z
      .string()
      .transform(val => parseInt(val, 10))
      .pipe(z.number().min(1).default(1))
      .optional(),
    limit: z
      .string()
      .transform(val => parseInt(val, 10))
      .pipe(z.number().min(1).max(100).default(10))
      .optional(),
    sort: z.string().optional(),
    order: z.enum(['asc', 'desc']).default('desc').optional(),
    search: z.string().optional()
  });

  // Validate with custom error handling
  static validate<T>(
    schema: z.ZodSchema<T>,
    data: unknown,
    context?: string
  ): { success: true; data: T } | { success: false; errors: string[] } {
    try {
      const result = schema.parse(data);
      return { success: true, data: result };
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        const errors = error.errors.map(err => {
          const path = err.path.join('.');
          return path ? `${path}: ${err.message}` : err.message;
        });

        logger.warn({
          type: 'VALIDATION',
          context,
          errors,
          data
        }, 'Validation failed');

        return { success: false, errors };
      }

      logger.error({
        type: 'VALIDATION_ERROR',
        context,
        error: error.message
      }, 'Unexpected validation error');

      return { 
        success: false, 
        errors: ['Validation failed'] 
      };
    }
  }

  // Safe parse with fallback
  static safeParse<T>(
    schema: z.ZodSchema<T>,
    data: unknown
  ): T | null {
    const result = schema.safeParse(data);
    return result.success ? result.data : null;
  }

  // Sanitize input
  static sanitize<T>(obj: T): T {
    if (typeof obj !== 'object' || obj === null) {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitize(item)) as any;
    }

    const sanitized: any = {};
    
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        // Remove potential XSS payloads
        sanitized[key] = value
          .replace(/[<>]/g, '') // Remove HTML tags
          .replace(/\0/g, '')   // Remove null bytes
          .trim();
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitize(value);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  // Check for SQL injection patterns
  static hasSQLInjection(input: string): boolean {
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)/i,
      /(\b(OR|AND)\b\s*[\d\w]+\s*=\s*[\d\w]+)/i,
      /(--|\/\*|\*\/|;)/,
      /(\b(EXEC|EXECUTE|DECLARE|CAST)\b)/i
    ];

    return sqlPatterns.some(pattern => pattern.test(input));
  }

  // Check for XSS patterns
  static hasXSS(input: string): boolean {
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /expression\s*\(/gi
    ];

    return xssPatterns.some(pattern => pattern.test(input));
  }

  // Validate and sanitize request body
  static validateRequest<T>(
    schema: z.ZodSchema<T>,
    data: unknown
  ): { isValid: boolean; data?: T; errors?: string[] } {
    // First sanitize
    const sanitized = this.sanitize(data);
    
    // Then validate
    const validation = this.validate(schema, sanitized);
    
    if (validation.success) {
      return { 
        isValid: true, 
        data: validation.data 
      };
    }
    
    return { 
      isValid: false, 
      errors: validation.errors 
    };
  }
}

// Common validation schemas
export const Schemas = {
  // User schemas
  user: {
    create: z.object({
      email: Validator.email,
      password: Validator.password,
      firstName: z.string().min(2).max(50).optional(),
      lastName: z.string().min(2).max(50).optional(),
      phone: Validator.phone
    }),
    
    update: z.object({
      firstName: z.string().min(2).max(50).optional(),
      lastName: z.string().min(2).max(50).optional(),
      phone: Validator.phone
    }),
    
    changePassword: z.object({
      currentPassword: z.string().min(1, 'Current password is required'),
      newPassword: Validator.password,
      confirmPassword: z.string()
    }).refine(data => data.newPassword === data.confirmPassword, {
      message: 'Passwords do not match',
      path: ['confirmPassword']
    })
  },
  
  // Auth schemas
  auth: {
    login: z.object({
      email: Validator.email,
      password: z.string().min(1, 'Password is required'),
      rememberMe: z.boolean().optional().default(false)
    }),
    
    register: z.object({
      email: Validator.email,
      password: Validator.password,
      confirmPassword: z.string(),
      firstName: z.string().min(2).max(50).optional(),
      lastName: z.string().min(2).max(50).optional(),
      phone: Validator.phone
    }).refine(data => data.password === data.confirmPassword, {
      message: 'Passwords do not match',
      path: ['confirmPassword']
    }),
    
    forgotPassword: z.object({
      email: Validator.email
    }),
    
    resetPassword: z.object({
      token: z.string().min(1, 'Token is required'),
      newPassword: Validator.password,
      confirmPassword: z.string()
    }).refine(data => data.newPassword === data.confirmPassword, {
      message: 'Passwords do not match',
      path: ['confirmPassword']
    })
  }
};