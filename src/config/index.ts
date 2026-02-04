import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config({
  path: path.resolve(
    process.cwd(),
    `.env.${process.env.NODE_ENV || 'development'}`
  ),
});

export const config = {
  // Server
  nodeEnv: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '3000'),
  apiPrefix: process.env.API_PREFIX || '/api',
  apiVersion: process.env.API_VERSION || 'v1',

  // JWT
  jwtAccessSecret: process.env.JWT_ACCESS_SECRET!,
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET!,
  jwtAccessExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
  jwtRefreshExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',

  // Security
  bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS || '12'),
  tokenBlacklistTtl: parseInt(process.env.TOKEN_BLACKLIST_TTL || '86400'),

  // Rate limiting
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),

  // Database
  databaseUrl: process.env.DATABASE_URL!,

  // Redis
  redisHost: process.env.REDIS_HOST || 'localhost',
  redisPort: parseInt(process.env.REDIS_PORT || '6379'),
  redisPassword: process.env.REDIS_PASSWORD || '',
  redisDb: parseInt(process.env.REDIS_DB || '0'),

  // CORS
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:3000',

  // Email (for production)
  smtpHost: process.env.SMTP_HOST,
  smtpPort: parseInt(process.env.SMTP_PORT || '587'),
  smtpUser: process.env.SMTP_USER,
  smtpPass: process.env.SMTP_PASS,

  // Validation
  passwordMinLength: 8,
  passwordMaxLength: 100,
};

// Validate required environment variables
const requiredEnvVars = [
  'JWT_ACCESS_SECRET',
  'JWT_REFRESH_SECRET',
  'DATABASE_URL',
];

requiredEnvVars.forEach(envVar => {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
});