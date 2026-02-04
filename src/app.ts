import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import mongoSanitize from 'express-mongo-sanitize';
import hpp from 'hpp';
import 'express-async-errors';
import { config } from './config';
import { initDatabase } from './config/database';
import { initRedis } from './config/redis';
import { AuthMiddleware } from './core/middlewares/auth.middleware';
import { ValidationMiddleware } from './core/middlewares/validation.middleware';
import { RateLimiter } from './core/security/rate-limiter';
import { sanitizer } from './core/security/sanitizer';
import { TokenService } from './core/security/token.service';
import { AuthService } from './modules/auth/services/auth.service';
import { AuthController } from './modules/auth/controllers/auth.controller';
import { authRoutes } from './modules/auth/routes/auth.routes';
import { errorHandler } from './core/middlewares/error.middleware';
import { logger } from './core/utils/logger';

class Application {
    private app: express.Application;
    private prisma = initDatabase();
    private redis = initRedis();
    private rateLimiter: RateLimiter;
    private tokenService: TokenService;
    private authService: AuthService;
    private authController: AuthController;
    private authMiddleware: AuthMiddleware;
    private validationMiddleware: ValidationMiddleware;

    constructor() {
        this.app = express();
        this.initializeServices();
        this.configureMiddleware();
        this.configureRoutes();
        this.configureErrorHandling();
    }

    private initializeServices(): void {
        // Initialize rate limiter
        this.rateLimiter = new RateLimiter(this.redis);

        // Initialize token service
        this.tokenService = new TokenService(this.redis);

        // Initialize auth service
        this.authService = new AuthService(
            this.prisma,
            this.redis,
            this.tokenService
        );

        // Initialize auth controller
        this.authController = new AuthController(
            this.authService,
            this.tokenService
        );

        // Initialize middleware
        this.authMiddleware = new AuthMiddleware(
            this.tokenService,
            this.prisma,
            this.redis
        );
        this.validationMiddleware = new ValidationMiddleware();
    }

    private configureMiddleware(): void {
        // Security headers
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'"],
                    fontSrc: ["'self'"],
                    objectSrc: ["'none'"],
                    mediaSrc: ["'self'"],
                    frameSrc: ["'none'"],
                },
            },
            crossOriginEmbedderPolicy: false,
        }));

        // CORS configuration
        this.app.use(cors({
            origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
            allowedHeaders: [
                'Content-Type',
                'Authorization',
                'X-Requested-With',
                'Accept',
                'Origin',
            ],
        }));

        // Compression
        this.app.use(compression());

        // Body parsing
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

        // Cookie parser
        this.app.use(cookieParser());

        // Sanitize data
        this.app.use(sanitizer.sanitizeRequest);
        this.app.use(mongoSanitize());
        this.app.use(hpp());

        // Rate limiting
        this.app.use('/api/auth/', this.rateLimiter.authLimiter);
        this.app.use('/api/', this.rateLimiter.generalLimiter);

        // Request logging
        this.app.use((req, res, next) => {
            logger.info(`${req.method} ${req.url}`, {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
            });
            next();
        });
    }

    private configureRoutes(): void {
        // Health check
        this.app.get('/health', (req, res) => {
            res.status(200).json({
                status: 'OK',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                environment: process.env.NODE_ENV,
            });
        });

        // API routes
        this.app.use('/api/auth', authRoutes(
            this.authController,
            this.authMiddleware,
            this.validationMiddleware
        ));

        // Protected example route
        this.app.get('/api/protected',
            this.authMiddleware.authenticate,
            (req, res) => {
                res.json({
                    message: 'Access granted to protected route',
                    user: req.user,
                });
            }
        );

        // Role-based example
        this.app.get('/api/admin',
            this.authMiddleware.authenticate,
            this.authMiddleware.authorize('ADMIN', 'SUPER_ADMIN'),
            (req, res) => {
                res.json({
                    message: 'Welcome, admin!',
                    user: req.user,
                });
            }
        );

        // 404 handler
        this.app.use('*', (req, res) => {
            res.status(404).json({
                error: 'Route not found',
                path: req.originalUrl,
                method: req.method,
            });
        });
    }

    private configureErrorHandling(): void {
        this.app.use(errorHandler);
    }

    public async start(): Promise<void> {
        try {
            // Test database connection
            await this.prisma.$connect();
            logger.info('Database connected successfully');

            // Test Redis connection
            await this.redis.ping();
            logger.info('Redis connected successfully');

            const port = config.port;
            this.app.listen(port, () => {
                logger.info(`Server running on port ${port}`);
                logger.info(`Environment: ${config.nodeEnv}`);
                logger.info(`API Base URL: http://localhost:${port}/api`);
            });
        } catch (error) {
            logger.error('Failed to start application:', error);
            process.exit(1);
        }
    }

    public async shutdown(): Promise<void> {
        try {
            await this.prisma.$disconnect();
            await this.redis.quit();
            logger.info('Application shutdown gracefully');
        } catch (error) {
            logger.error('Error during shutdown:', error);
        } finally {
            process.exit(0);
        }
    }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
    logger.info('SIGINT received, starting graceful shutdown');
    const app = new Application();
    app.shutdown();
});

process.on('SIGTERM', () => {
    logger.info('SIGTERM received, starting graceful shutdown');
    const app = new Application();
    app.shutdown();
});

// Create and start application
const app = new Application();
app.start().catch(error => {
    logger.error('Application failed to start:', error);
    process.exit(1);
});

export { Application };