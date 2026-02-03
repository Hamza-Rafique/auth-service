// src/core/security/token.service.ts
import jwt from 'jsonwebtoken';
import { Redis } from 'ioredis';
import crypto from 'crypto';

export interface TokenPayload {
  userId: string;
  email: string;
  role: string;
  sessionId?: string;
}

export interface GeneratedTokens {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiry: Date;
  refreshTokenExpiry: Date;
}

export class TokenService {
  private readonly accessSecret: string;
  private readonly refreshSecret: string;
  private readonly accessExpiry: string;
  private readonly refreshExpiry: string;
  private readonly blacklistTtl: number;

  constructor(private redisClient: Redis) {
    this.accessSecret = process.env.JWT_ACCESS_SECRET!;
    this.refreshSecret = process.env.JWT_REFRESH_SECRET!;
    this.accessExpiry = process.env.JWT_ACCESS_EXPIRY || '15m';
    this.refreshExpiry = process.env.JWT_REFRESH_EXPIRY || '7d';
    this.blacklistTtl = parseInt(process.env.TOKEN_BLACKLIST_TTL || '86400');
  }

  // Generate access token
  generateAccessToken(payload: TokenPayload): string {
    return jwt.sign(
      {
        ...payload,
        type: 'access',
      },
      this.accessSecret,
      {
        expiresIn: this.accessExpiry,
        issuer: 'auth-service',
        audience: 'user',
      }
    );
  }

  // Generate refresh token
  generateRefreshToken(payload: TokenPayload): string {
    return jwt.sign(
      {
        ...payload,
        type: 'refresh',
      },
      this.refreshSecret,
      {
        expiresIn: this.refreshExpiry,
        issuer: 'auth-service',
        audience: 'user',
      }
    );
  }

  // Generate both tokens
  generateTokens(payload: TokenPayload): GeneratedTokens {
    const accessToken = this.generateAccessToken(payload);
    const refreshToken = this.generateRefreshToken(payload);
    
    // Calculate expiry dates
    const accessTokenExpiry = new Date();
    accessTokenExpiry.setMinutes(accessTokenExpiry.getMinutes() + 15);
    
    const refreshTokenExpiry = new Date();
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);

    return {
      accessToken,
      refreshToken,
      accessTokenExpiry,
      refreshTokenExpiry,
    };
  }

  // Verify access token
  verifyAccessToken(token: string): TokenPayload {
    try {
      const decoded = jwt.verify(token, this.accessSecret, {
        issuer: 'auth-service',
        audience: 'user',
      }) as TokenPayload & { type: string };
      
      if (decoded.type !== 'access') {
        throw new Error('Invalid token type');
      }
      
      return decoded;
    } catch (error) {
      throw new Error('Invalid access token');
    }
  }

  // Verify refresh token
  verifyRefreshToken(token: string): TokenPayload {
    try {
      const decoded = jwt.verify(token, this.refreshSecret, {
        issuer: 'auth-service',
        audience: 'user',
      }) as TokenPayload & { type: string };
      
      if (decoded.type !== 'refresh') {
        throw new Error('Invalid token type');
      }
      
      return decoded;
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  // Blacklist token
  async blacklistToken(token: string, userId: string): Promise<void> {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const key = `blacklist:${userId}:${tokenHash}`;
    
    await this.redisClient.setex(key, this.blacklistTtl, '1');
  }

  // Check if token is blacklisted
  async isTokenBlacklisted(token: string, userId: string): Promise<boolean> {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const key = `blacklist:${userId}:${tokenHash}`;
    
    const result = await this.redisClient.get(key);
    return result === '1';
  }

  // Decode token without verification (for logging)
  decodeToken(token: string): any {
    return jwt.decode(token);
  }
}