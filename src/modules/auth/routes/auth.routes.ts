import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { AuthMiddleware } from '../../../core/middlewares/auth.middleware';
import { ValidationMiddleware } from '../../../core/middlewares/validation.middleware';
import {
    registerSchema,
    loginSchema,
    forgotPasswordSchema,
    resetPasswordSchema,
    changePasswordSchema,
    verifyEmailSchema,
} from '../dto/auth.dto';

export const authRoutes = (
    authController: AuthController,
    authMiddleware: AuthMiddleware,
    validationMiddleware: ValidationMiddleware
): Router => {
    const router = Router();

    // Public routes
    router.post(
        '/register',
        validationMiddleware.validateBody(registerSchema),
        authController.register
    );

    router.post(
        '/login',
        validationMiddleware.validateBody(loginSchema),
        authController.login
    );

    router.post(
        '/refresh-token',
        authController.refreshToken
    );

    router.post(
        '/forgot-password',
        validationMiddleware.validateBody(forgotPasswordSchema),
        authController.forgotPassword
    );

    router.post(
        '/reset-password',
        validationMiddleware.validateBody(resetPasswordSchema),
        authController.resetPassword
    );

    router.post(
        '/verify-email',
        validationMiddleware.validateBody(verifyEmailSchema),
        authController.verifyEmail
    );

    // Protected routes
    router.post(
        '/logout',
        authMiddleware.authenticate,
        authController.logout
    );

    router.post(
        '/change-password',
        authMiddleware.authenticate,
        validationMiddleware.validateBody(changePasswordSchema),
        authController.changePassword
    );

    router.get(
        '/profile',
        authMiddleware.authenticate,
        authController.getProfile
    );

    router.get(
        '/sessions',
        authMiddleware.authenticate,
        authController.getSessions
    );

    router.delete(
        '/sessions/:sessionId',
        authMiddleware.authenticate,
        authController.revokeSession
    );

    return router;
};