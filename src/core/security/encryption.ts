import bcrypt from 'bcrypt';
import * as argon2 from 'argon2';
import crypto from 'crypto';

export class EncryptionService {
  private readonly bcryptSaltRounds: number;
  
  constructor() {
    this.bcryptSaltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12');
  }

  // Hash password with Argon2 (recommended)
  async hashPassword(password: string): Promise<string> {
    try {
      return await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 2 ** 16,
        timeCost: 3,
        parallelism: 1,
      });
    } catch (error) {
      // Fallback to bcrypt if Argon2 fails
      return this.hashWithBcrypt(password);
    }
  }

  // Bcrypt fallback
  async hashWithBcrypt(password: string): Promise<string> {
    return bcrypt.hash(password, this.bcryptSaltRounds);
  }

  // Verify password
  async verifyPassword(
    hashedPassword: string,
    plainPassword: string
  ): Promise<boolean> {
    try {
      // Try Argon2 first
      if (hashedPassword.startsWith('$argon2')) {
        return await argon2.verify(hashedPassword, plainPassword);
      }
      // Fallback to bcrypt
      return bcrypt.compare(plainPassword, hashedPassword);
    } catch (error) {
      throw new Error('Password verification failed');
    }
  }

  // Generate random tokens
  generateRandomToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  // Timing safe comparison
  timingSafeEqual(a: string, b: string): boolean {
    try {
      return crypto.timingSafeEqual(
        Buffer.from(a, 'utf8'),
        Buffer.from(b, 'utf8')
      );
    } catch {
      return false;
    }
  }

  // Generate secure random bytes
  generateSecureRandomBytes(size: number): Buffer {
    return crypto.randomBytes(size);
  }
}

export const encryptionService = new EncryptionService();