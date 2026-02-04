import { PrismaClient } from '@prisma/client';
import { Redis } from 'ioredis';
import {
  RegisterDto,
  LoginDto,
  RefreshTokenDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  ChangePasswordDto,
  VerifyEmailDto,
} from '../dto/auth.dto';
import { TokenService, TokenPayload } from '../../../core/security/token.service';
import { encryptionService } from '../../../core/security/encryption';
import { v4 as uuidv4 } from 'uuid';

export interface AuthResponse {
  user: {
    id: string;
    email: string;
    firstName?: string | null;
    lastName?: string | null;
    role: string;
    isVerified: boolean;
  };
  tokens: {
    accessToken: string;
    refreshToken: string;
    accessTokenExpiry: Date;
    refreshTokenExpiry: Date;
  };
  session: {
    id: string;
    deviceInfo?: string;
    ipAddress?: string;
    lastActiveAt: Date;
  };
}

export class AuthService {
  constructor(
    private prisma: PrismaClient,
    private redis: Redis,
    private tokenService: TokenService
  ) { }

  // Register new user
  async register(data: RegisterDto, ipAddress?: string): Promise<AuthResponse> {
    // Check if user already exists
    const existingUser = await this.prisma.user.findUnique({
      where: { email: data.email },
    });

    if (existingUser) {
      throw new Error('User already exists');
    }

    // Hash password
    const passwordHash = await encryptionService.hashPassword(data.password);

    // Create user
    const user = await this.prisma.user.create({
      data: {
        email: data.email,
        passwordHash,
        firstName: data.firstName,
        lastName: data.lastName,
        phone: data.phone,
      },
    });

    // Create session
    const session = await this.prisma.session.create({
      data: {
        userId: user.id,
        deviceInfo: data.deviceInfo,
        ipAddress,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      },
    });

    // Generate tokens
    const tokenPayload: TokenPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      sessionId: session.id,
    };

    const tokens = this.tokenService.generateTokens(tokenPayload);

    // Create refresh token record
    await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        token: tokens.refreshToken,
        deviceInfo: data.deviceInfo,
        ipAddress,
        expiresAt: tokens.refreshTokenExpiry,
      },
    });

    // Send verification email (async)
    await this.sendVerificationEmail(user.id, user.email);

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isVerified: user.isVerified,
      },
      tokens,
      session: {
        id: session.id,
        deviceInfo: session.deviceInfo,
        ipAddress: session.ipAddress ,
        lastActiveAt: session.lastActiveAt,
      },
    };
  }

  // Login user
  async login(data: LoginDto, ipAddress?: string): Promise<AuthResponse> {
    // Find user
    const user = await this.prisma.user.findUnique({
      where: { email: data.email },
    });

    if (!user) {
      throw new Error('Invalid credentials');
    }

    // Check if account is locked
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new Error('Account is temporarily locked');
    }

    // Verify password
    const isValidPassword = await encryptionService.verifyPassword(
      user.passwordHash,
      data.password
    );

    if (!isValidPassword) {
      // Increment failed login attempts
      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: user.failedLoginAttempts + 1,
          lockedUntil:
            user.failedLoginAttempts + 1 >= 5
              ? new Date(Date.now() + 15 * 60 * 1000) // 15 minutes lock
              : null,
        },
      });

      throw new Error('Invalid credentials');
    }

    // Reset failed login attempts on successful login
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lockedUntil: null,
        lastLoginAt: new Date(),
      },
    });

    // Create session
    const session = await this.prisma.session.create({
      data: {
        userId: user.id,
        deviceInfo: data.deviceInfo,
        ipAddress,
        expiresAt: data.rememberMe
          ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
          : new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      },
    });

    // Generate tokens
    const tokenPayload: TokenPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      sessionId: session.id,
    };

    const tokens = this.tokenService.generateTokens(tokenPayload);

    // Create refresh token record
    await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        token: tokens.refreshToken,
        deviceInfo: data.deviceInfo,
        ipAddress,
        expiresAt: tokens.refreshTokenExpiry,
      },
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isVerified: user.isVerified,
      },
      tokens,
      session: {
        id: session.id,
        deviceInfo: session.deviceInfo,
        ipAddress: session.ipAddress,
        lastActiveAt: session.lastActiveAt,
      },
    };
  }

  // Refresh access token
  async refreshTokens(data: RefreshTokenDto): Promise<{
    accessToken: string;
    refreshToken: string;
    accessTokenExpiry: Date;
    refreshTokenExpiry: Date;
  }> {
    // Verify refresh token
    const payload = this.tokenService.verifyRefreshToken(data.refreshToken);

    // Check if refresh token exists and is not revoked
    const refreshTokenRecord = await this.prisma.refreshToken.findFirst({
      where: {
        token: data.refreshToken,
        userId: payload.userId,
        isRevoked: false,
        expiresAt: { gt: new Date() },
      },
      include: { user: true },
    });

    if (!refreshTokenRecord || !refreshTokenRecord.user.isActive) {
      throw new Error('Invalid refresh token');
    }

    // Mark old refresh token as revoked
    await this.prisma.refreshToken.update({
      where: { id: refreshTokenRecord.id },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
      },
    });

    // Get current session or create new one
    let session = await this.prisma.session.findFirst({
      where: {
        userId: payload.userId,
        isValid: true,
        expiresAt: { gt: new Date() },
      },
      orderBy: { lastActiveAt: 'desc' },
    });

    if (!session) {
      session = await this.prisma.session.create({
        data: {
          userId: payload.userId,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
        },
      });
    }

    // Generate new tokens
    const newTokenPayload: TokenPayload = {
      userId: payload.userId,
      email: payload.email,
      role: payload.role,
      sessionId: session.id,
    };

    const newTokens = this.tokenService.generateTokens(newTokenPayload);

    // Create new refresh token record
    await this.prisma.refreshToken.create({
      data: {
        userId: payload.userId,
        token: newTokens.refreshToken,
        deviceInfo: refreshTokenRecord.deviceInfo,
        ipAddress: refreshTokenRecord.ipAddress,
        expiresAt: newTokens.refreshTokenExpiry,
        replacedBy: newTokens.refreshToken,
      },
    });

    return newTokens;
  }

  // Logout
  async logout(userId: string, sessionId?: string, accessToken?: string): Promise<void> {
    if (accessToken) {
      // Blacklist access token
      await this.tokenService.blacklistToken(accessToken, userId);
    }

    if (sessionId) {
      // Invalidate session
      await this.prisma.session.update({
        where: { id: sessionId },
        data: { isValid: false },
      });
    } else {
      // Invalidate all user sessions
      await this.prisma.session.updateMany({
        where: { userId, isValid: true },
        data: { isValid: false },
      });
    }

    // Revoke all refresh tokens for user
    await this.prisma.refreshToken.updateMany({
      where: { userId, isRevoked: false },
      data: { isRevoked: true, revokedAt: new Date() },
    });
  }

  // Forgot password
  async forgotPassword(data: ForgotPasswordDto): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { email: data.email },
    });

    if (!user) {
      // Return success even if user doesn't exist (security through obscurity)
      return;
    }

    // Generate reset token
    const resetToken = uuidv4();
    const expiresAt = new Date(Date.now() + 1 * 60 * 60 * 1000); // 1 hour

    // Store reset token
    await this.prisma.passwordReset.create({
      data: {
        userId: user.id,
        token: resetToken,
        expiresAt,
      },
    });

    // Send reset email (implement email service)
    await this.sendPasswordResetEmail(user.email, resetToken);
  }

  // Reset password
  async resetPassword(data: ResetPasswordDto): Promise<void> {
    // Find valid reset token
    const resetRecord = await this.prisma.passwordReset.findFirst({
      where: {
        token: data.token,
        isUsed: false,
        expiresAt: { gt: new Date() },
      },
      include: { user: true },
    });

    if (!resetRecord) {
      throw new Error('Invalid or expired reset token');
    }

    // Hash new password
    const passwordHash = await encryptionService.hashPassword(data.newPassword);

    // Update user password
    await this.prisma.user.update({
      where: { id: resetRecord.userId },
      data: { passwordHash },
    });

    // Mark reset token as used
    await this.prisma.passwordReset.update({
      where: { id: resetRecord.id },
      data: { isUsed: true, usedAt: new Date() },
    });

    // Invalidate all user sessions and tokens
    await this.logout(resetRecord.userId);

    // Send password changed notification
    await this.sendPasswordChangedNotification(resetRecord.user.email);
  }

  // Change password (authenticated)
  async changePassword(
    userId: string,
    data: ChangePasswordDto
  ): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new Error('User not found');
    }

    // Verify current password
    const isValidPassword = await encryptionService.verifyPassword(
      user.passwordHash,
      data.currentPassword
    );

    if (!isValidPassword) {
      throw new Error('Current password is incorrect');
    }

    // Hash new password
    const passwordHash = await encryptionService.hashPassword(data.newPassword);

    // Update password
    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash },
    });

    // Invalidate all sessions except current
    await this.prisma.session.updateMany({
      where: {
        userId,
        isValid: true,
      },
      data: { isValid: false },
    });

    // Send password changed notification
    await this.sendPasswordChangedNotification(user.email);
  }

  // Verify email
  async verifyEmail(data: VerifyEmailDto): Promise<void> {
    // In production, verify token from email
    // For now, just mark as verified if token is valid
    const user = await this.prisma.user.findFirst({
      where: {
        email: data.token, // token is email in this simple implementation
        isVerified: false,
      },
    });

    if (!user) {
      throw new Error('Invalid verification token');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true },
    });
  }

  // Get user sessions
  async getUserSessions(userId: string) {
    return this.prisma.session.findMany({
      where: { userId, isValid: true, expiresAt: { gt: new Date() } },
      orderBy: { lastActiveAt: 'desc' },
    });
  }

  // Revoke session
  async revokeSession(userId: string, sessionId: string): Promise<void> {
    await this.prisma.session.update({
      where: { id: sessionId, userId },
      data: { isValid: false },
    });
  }

  // Private helper methods
  private async sendVerificationEmail(userId: string, email: string): Promise<void> {
    // Implement email sending logic
    console.log(`Verification email sent to ${email}`);
  }

  private async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    // Implement email sending logic
    console.log(`Password reset email sent to ${email} with token ${token}`);
  }

  private async sendPasswordChangedNotification(email: string): Promise<void> {
    // Implement email sending logic
    console.log(`Password change notification sent to ${email}`);
  }
}