// src/core/middlewares/auth.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { TokenService } from '../security/token.service';
import { Redis } from 'ioredis';
import { PrismaClient } from '@prisma/client';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        role: string;
        sessionId?: string;
      };
    }
  }
}

export class AuthMiddleware {
  constructor(
    private tokenService: TokenService,
    private prisma: PrismaClient,
    private redis: Redis
  ) {}

  // Main authentication middleware
  authenticate = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          error: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
      }

      const token = authHeader.substring(7);
      
      // Verify token
      const payload = this.tokenService.verifyAccessToken(token);
      
      // Check if token is blacklisted
      const isBlacklisted = await this.tokenService.isTokenBlacklisted(
        token,
        payload.userId
      );
      
      if (isBlacklisted) {
        return res.status(401).json({
          error: 'Token has been revoked',
          code: 'TOKEN_REVOKED',
        });
      }

      // Check if user exists and is active
      const user = await this.prisma.user.findUnique({
        where: { id: payload.userId, isActive: true },
        select: { id: true, email: true, role: true, isVerified: true },
      });

      if (!user) {
        return res.status(401).json({
          error: 'User not found or inactive',
          code: 'USER_INACTIVE',
        });
      }

      // Check if session is valid (if sessionId exists in token)
      if (payload.sessionId) {
        const session = await this.prisma.session.findFirst({
          where: {
            id: payload.sessionId,
            userId: payload.userId,
            isValid: true,
            expiresAt: { gt: new Date() },
          },
        });

        if (!session) {
          return res.status(401).json({
            error: 'Session expired or invalid',
            code: 'SESSION_INVALID',
          });
        }
      }

      // Attach user to request
      req.user = {
        id: user.id,
        email: user.email,
        role: user.role,
        sessionId: payload.sessionId,
      };

      next();
    } catch (error: any) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
          error: 'Token expired',
          code: 'TOKEN_EXPIRED',
        });
      }

      return res.status(401).json({
        error: 'Invalid token',
        code: 'INVALID_TOKEN',
      });
    }
  };

  // Role-based authorization
  authorize = (...allowedRoles: string[]) => {
    return (req: Request, res: Response, next: NextFunction) => {
      if (!req.user) {
        return res.status(401).json({
          error: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
      }

      if (!allowedRoles.includes(req.user.role)) {
        return res.status(403).json({
          error: 'Insufficient permissions',
          code: 'INSUFFICIENT_PERMISSIONS',
          required: allowedRoles,
          current: req.user.role,
        });
      }

      next();
    };
  };

  // Optional authentication (doesn't fail if no token)
  optionalAuth = async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }

    try {
      const token = authHeader.substring(7);
      const payload = this.tokenService.verifyAccessToken(token);
      
      const isBlacklisted = await this.tokenService.isTokenBlacklisted(
        token,
        payload.userId
      );
      
      if (!isBlacklisted) {
        const user = await this.prisma.user.findUnique({
          where: { id: payload.userId, isActive: true },
          select: { id: true, email: true, role: true },
        });

        if (user) {
          req.user = {
            id: user.id,
            email: user.email,
            role: user.role,
            sessionId: payload.sessionId,
          };
        }
      }
    } catch (error) {
      // Silently ignore invalid tokens for optional auth
    }

    next();
  };
}