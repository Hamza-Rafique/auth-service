import { Request, Response } from 'express';
import { AuthService } from '../services/auth.service';
import { TokenService } from '../../../core/security/token.service';
import { sanitizer } from '../../../core/security/sanitizer';
import {
  registerSchema,
  loginSchema,
  refreshTokenSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
  verifyEmailSchema,
} from '../dto/auth.dto';

export class AuthController {
  constructor(
    private authService: AuthService,
    private tokenService: TokenService
  ) {}

  // Register user
  register = async (req: Request, res: Response) => {
    try {
      // Validate and sanitize input
      const validatedData = registerSchema.parse(req.body);
      const sanitizedData = sanitizer.deepSanitize(validatedData);

      // Get client IP
      const ipAddress = req.ip || req.headers['x-forwarded-for'] || 'unknown';

      // Register user
      const result = await this.authService.register(sanitizedData, ipAddress);

      // Set refresh token as HTTP-only cookie
      res.cookie('refreshToken', result.tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      // Return response
      res.status(201).json({
        success: true,
        data: {
          user: result.user,
          accessToken: result.tokens.accessToken,
          accessTokenExpiry: result.tokens.accessTokenExpiry,
          session: result.session,
        },
        message: 'Registration successful. Please verify your email.',
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        error: error.message,
        code: 'REGISTRATION_FAILED',
      });
    }
  };

  // Login user
  login = async (req: Request, res: Response) => {
    try {
      // Validate and sanitize input
      const validatedData = loginSchema.parse(req.body);
      const sanitizedData = sanitizer.deepSanitize(validatedData);

      // Get client IP
      const ipAddress = req.ip || req.headers['x-forwarded-for'] || 'unknown';

      // Login user
      const result = await this.authService.login(sanitizedData, ipAddress);

      // Set refresh token as HTTP-only cookie
      res.cookie('refreshToken', result.tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: sanitizedData.rememberMe
          ? 30 * 24 * 60 * 60 * 1000 // 30 days
          : 24 * 60 * 60 * 1000, // 24 hours
      });

      // Return response
      res.status(200).json({
        success: true,
        data: {
          user: result.user,
          accessToken: result.tokens.accessToken,
          accessTokenExpiry: result.tokens.accessTokenExpiry,
          session: result.session,
        },
        message: 'Login successful',
      });
    } catch (error: any) {
      res.status(401).json({
        success: false,
        error: error.message,
        code: 'LOGIN_FAILED',
      });
    }
  };

  // Refresh token
  refreshToken = async (req: Request, res: Response) => {
    try {
      // Get refresh token from cookie or body
      const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

      if (!refreshToken) {
        throw new Error('Refresh token required');
      }

      const validatedData = refreshTokenSchema.parse({ refreshToken });

      // Refresh tokens
      const tokens = await this.authService.refreshTokens(validatedData);

      // Set new refresh token as HTTP-only cookie
      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      // Return new access token
      res.status(200).json({
        success: true,
        data: {
          accessToken: tokens.accessToken,
          accessTokenExpiry: tokens.accessTokenExpiry,
        },
        message: 'Token refreshed successfully',
      });
    } catch (error: any) {
      // Clear invalid refresh token cookie
      res.clearCookie('refreshToken');

      res.status(401).json({
        success: false,
        error: error.message,
        code: 'TOKEN_REFRESH_FAILED',
      });
    }
  };

  // Logout
  logout = async (req: Request, res: Response) => {
    try {
      const userId = req.user?.id;
      const sessionId = req.user?.sessionId;
      const accessToken = req.headers.authorization?.substring(7);

      if (!userId) {
        throw new Error('User not authenticated');
      }

      await this.authService.logout(userId, sessionId, accessToken);

      // Clear refresh token cookie
      res.clearCookie('refreshToken');

      res.status(200).json({
        success: true,
        message: 'Logout successful',
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        error: error.message,
        code: 'LOGOUT_FAILED',
      });
    }
  };

  // Forgot password
  forgotPassword = async (req: Request, res: Response) => {
    try {
      const validatedData = forgotPasswordSchema.parse(req.body);
      const sanitizedData = sanitizer.deepSanitize(validatedData);

      await this.authService.forgotPassword(sanitizedData);

      // Always return success (security through obscurity)
      res.status(200).json({
        success: true,
        message: 'If an account exists, a password reset email has been sent.',
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        error: error.message,
        code: 'PASSWORD_RESET_REQUEST_FAILED',
      });
    }
  };

  // Reset password
  resetPassword = async (req: Request, res: Response) => {
    try {
      const validatedData = resetPasswordSchema.parse(req.body);
      const sanitizedData = sanitizer.deepSanitize(validatedData);

      await this.authService.resetPassword(sanitizedData);

      res.status(200).json({
        success: true,
        message: 'Password reset successful. Please login with your new password.',
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        error: error.message,
        code: 'PASSWORD_RESET_FAILED',
      });
    }
  };

  // Change password (authenticated)
  changePassword = async (req: Request, res: Response) => {
    try {
      const userId = req.user?.id;

      if (!userId) {
        throw new Error('User not authenticated');
      }

      const validatedData = changePasswordSchema.parse(req.body);
      const sanitizedData = sanitizer.deepSanitize(validatedData);

      await this.authService.changePassword(userId, sanitizedData);

      res.status(200).json({
        success: true,
        message: 'Password changed successfully',
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        error: error.message,
        code: 'PASSWORD_CHANGE_FAILED',
      });
    }
  };

  // Verify email
  verifyEmail = async (req: Request, res: Response) => {
    try {
      const validatedData = verifyEmailSchema.parse(req.body);
      const sanitizedData = sanitizer.deepSanitize(validatedData);

      await this.authService.verifyEmail(sanitizedData);

      res.status(200).json({
        success: true,
        message: 'Email verified successfully',
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        error: error.message,
        code: 'EMAIL_VERIFICATION_FAILED',
      });
    }
  };

  // Get current user sessions
  getSessions = async (req: Request, res: Response) => {
    try {
      const userId = req.user?.id;

      if (!userId) {
        throw new Error('User not authenticated');
      }

      const sessions = await this.authService.getUserSessions(userId);

      res.status(200).json({
        success: true,
        data: sessions,
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        error: error.message,
        code: 'SESSIONS_FETCH_FAILED',
      });
    }
  };

  // Revoke session
  revokeSession = async (req: Request, res: Response) => {
    try {
      const userId = req.user?.id;
      const { sessionId } = req.params;

      if (!userId) {
        throw new Error('User not authenticated');
      }

      await this.authService.revokeSession(userId, sessionId);

      res.status(200).json({
        success: true,
        message: 'Session revoked successfully',
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        error: error.message,
        code: 'SESSION_REVOCATION_FAILED',
      });
    }
  };

  // Get current user profile
  getProfile = async (req: Request, res: Response) => {
    try {
      const user = req.user;

      if (!user) {
        throw new Error('User not authenticated');
      }

      res.status(200).json({
        success: true,
        data: user,
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        error: error.message,
        code: 'PROFILE_FETCH_FAILED',
      });
    }
  };
}