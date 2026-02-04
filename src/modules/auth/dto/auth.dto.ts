import { z } from 'zod';

// Registration DTO
export const registerSchema = z.object({
  email: z.string()
    .email('Invalid email format')
    .min(5, 'Email too short')
    .max(255, 'Email too long')
    .transform(email => email.toLowerCase().trim()),
  
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(100, 'Password too long')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      'Password must contain uppercase, lowercase, number, and special character'
    ),
  
  confirmPassword: z.string(),
  
  firstName: z.string()
    .min(2, 'First name too short')
    .max(50, 'First name too long')
    .optional(),
  
  lastName: z.string()
    .min(2, 'Last name too short')
    .max(50, 'Last name too long')
    .optional(),
  
  phone: z.string()
    .regex(/^\+?[\d\s\-\(\)]+$/, 'Invalid phone number')
    .optional(),
})
.refine(data => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

export type RegisterDto = z.infer<typeof registerSchema>;

// Login DTO
export const loginSchema = z.object({
  email: z.string()
    .email('Invalid email format')
    .transform(email => email.toLowerCase().trim()),
  
  password: z.string(),
  
  deviceInfo: z.string().optional(),
  
  rememberMe: z.boolean().optional().default(false),
});

export type LoginDto = z.infer<typeof loginSchema>;

// Refresh Token DTO
export const refreshTokenSchema = z.object({
  refreshToken: z.string(),
});

export type RefreshTokenDto = z.infer<typeof refreshTokenSchema>;

// Forgot Password DTO
export const forgotPasswordSchema = z.object({
  email: z.string()
    .email('Invalid email format')
    .transform(email => email.toLowerCase().trim()),
});

export type ForgotPasswordDto = z.infer<typeof forgotPasswordSchema>;

// Reset Password DTO
export const resetPasswordSchema = z.object({
  token: z.string(),
  
  newPassword: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(100, 'Password too long')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      'Password must contain uppercase, lowercase, number, and special character'
    ),
  
  confirmPassword: z.string(),
})
.refine(data => data.newPassword === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

export type ResetPasswordDto = z.infer<typeof resetPasswordSchema>;

// Change Password DTO
export const changePasswordSchema = z.object({
  currentPassword: z.string(),
  
  newPassword: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(100, 'Password too long')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      'Password must contain uppercase, lowercase, number, and special character'
    ),
  
  confirmPassword: z.string(),
})
.refine(data => data.newPassword === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

export type ChangePasswordDto = z.infer<typeof changePasswordSchema>;

// Verify Email DTO
export const verifyEmailSchema = z.object({
  token: z.string(),
});

export type VerifyEmailDto = z.infer<typeof verifyEmailSchema>;