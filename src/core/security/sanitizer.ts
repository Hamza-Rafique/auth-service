// src/core/security/sanitizer.ts
import sanitizeHtml from 'sanitize-html';
import { Request, Response, NextFunction } from 'express';

export class Sanitizer {
  // HTML sanitization options
  private htmlSanitizeOptions = {
    allowedTags: [], // No HTML tags allowed by default
    allowedAttributes: {},
  };

  // Deep sanitize object
  deepSanitize<T>(obj: T): T {
    if (!obj || typeof obj !== 'object') return obj;

    if (Array.isArray(obj)) {
      return obj.map(item => this.deepSanitize(item)) as any;
    }

    const sanitized: any = {};
    
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        sanitized[key] = this.sanitizeString(value);
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.deepSanitize(value);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  // Sanitize string
  sanitizeString(input: string): string {
    if (!input) return input;
    
    // Trim whitespace
    let sanitized = input.trim();
    
    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');
    
    // Sanitize HTML
    sanitized = sanitizeHtml(sanitized, this.htmlSanitizeOptions);
    
    // Remove excessive whitespace
    sanitized = sanitized.replace(/\s+/g, ' ');
    
    return sanitized;
  }

  // Email sanitization
  sanitizeEmail(email: string): string {
    const sanitized = this.sanitizeString(email).toLowerCase();
    
    // Basic email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(sanitized)) {
      throw new Error('Invalid email format');
    }
    
    return sanitized;
  }

  // SQL injection prevention
  containsSQLInjection(input: string): boolean {
    const sqlKeywords = [
      'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION',
      'OR', 'AND', 'WHERE', 'FROM', 'TABLE', 'DATABASE'
    ];
    
    const upperInput = input.toUpperCase();
    return sqlKeywords.some(keyword => 
      upperInput.includes(keyword) && 
      /[=\s]/.test(upperInput.charAt(upperInput.indexOf(keyword) - 1))
    );
  }

  // Middleware for request body sanitization
  sanitizeRequest = (req: Request, res: Response, next: NextFunction) => {
    if (req.body) {
      req.body = this.deepSanitize(req.body);
    }
    
    if (req.query) {
      req.query = this.deepSanitize(req.query);
    }
    
    if (req.params) {
      req.params = this.deepSanitize(req.params);
    }
    
    next();
  };
}

export const sanitizer = new Sanitizer();