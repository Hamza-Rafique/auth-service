import crypto from 'crypto';

export class StringUtil {
  // Generate random string
  static random(length: number = 32): string {
    return crypto
      .randomBytes(Math.ceil(length / 2))
      .toString('hex')
      .slice(0, length);
  }

  // Generate UUID
  static uuid(): string {
    return crypto.randomUUID();
  }

  // Hash string
  static hash(input: string, algorithm: string = 'sha256'): string {
    return crypto.createHash(algorithm).update(input).digest('hex');
  }

  // Generate token
  static generateToken(length: number = 64): string {
    return this.random(length);
  }

  // Generate verification code
  static generateVerificationCode(length: number = 6): string {
    const digits = '0123456789';
    let code = '';
    
    for (let i = 0; i < length; i++) {
      code += digits[Math.floor(Math.random() * digits.length)];
    }
    
    return code;
  }

  // Generate recovery code (with dashes)
  static generateRecoveryCode(): string {
    const parts = [
      this.random(8),
      this.random(4),
      this.random(4),
      this.random(12)
    ];
    
    return parts.join('-').toUpperCase();
  }

  // Mask sensitive data
  static mask(
    input: string,
    visibleChars: number = 4,
    maskChar: string = '*'
  ): string {
    if (!input || input.length <= visibleChars * 2) {
      return maskChar.repeat(input?.length || 0);
    }

    const firstVisible = input.slice(0, visibleChars);
    const lastVisible = input.slice(-visibleChars);
    const middleMask = maskChar.repeat(input.length - visibleChars * 2);

    return `${firstVisible}${middleMask}${lastVisible}`;
  }

  // Mask email
  static maskEmail(email: string): string {
    const [local, domain] = email.split('@');
    
    if (!local || !domain) {
      return email;
    }

    const maskedLocal = this.mask(local, 2);
    return `${maskedLocal}@${domain}`;
  }

  // Mask phone number
  static maskPhone(phone: string): string {
    const cleaned = phone.replace(/\D/g, '');
    
    if (cleaned.length <= 4) {
      return this.mask(phone, 0);
    }

    const lastFour = cleaned.slice(-4);
    return `*******${lastFour}`;
  }

  // Capitalize first letter
  static capitalize(input: string): string {
    if (!input) return input;
    return input.charAt(0).toUpperCase() + input.slice(1).toLowerCase();
  }

  // Convert to snake_case
  static toSnakeCase(input: string): string {
    return input
      .replace(/([a-z])([A-Z])/g, '$1_$2')
      .replace(/\s+/g, '_')
      .toLowerCase();
  }

  // Convert to camelCase
  static toCamelCase(input: string): string {
    return input
      .replace(/([-_][a-z])/g, group =>
        group.toUpperCase().replace('-', '').replace('_', '')
      )
      .replace(/^\w/, c => c.toLowerCase());
  }

  // Convert to PascalCase
  static toPascalCase(input: string): string {
    const camelCase = this.toCamelCase(input);
    return camelCase.charAt(0).toUpperCase() + camelCase.slice(1);
  }

  // Generate slug
  static generateSlug(input: string): string {
    return input
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/--+/g, '-')
      .trim();
  }

  // Truncate string
  static truncate(
    input: string,
    length: number = 100,
    suffix: string = '...'
  ): string {
    if (input.length <= length) {
      return input;
    }
    
    return input.slice(0, length - suffix.length) + suffix;
  }

  // Check if string is empty or whitespace
  static isEmpty(input: string): boolean {
    return !input || input.trim().length === 0;
  }

  // Check if string contains only numbers
  static isNumeric(input: string): boolean {
    return /^\d+$/.test(input);
  }

  // Check if string is valid JSON
  static isValidJSON(input: string): boolean {
    try {
      JSON.parse(input);
      return true;
    } catch {
      return false;
    }
  }

  // Generate password
  static generatePassword(length: number = 12): string {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let password = '';
    
    // Ensure at least one of each required character type
    const required = [
      'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)],
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)],
      '0123456789'[Math.floor(Math.random() * 10)],
      '!@#$%^&*'[Math.floor(Math.random() * 8)]
    ];
    
    password += required.join('');
    
    // Fill remaining characters
    for (let i = password.length; i < length; i++) {
      password += charset[Math.floor(Math.random() * charset.length)];
    }
    
    // Shuffle the password
    return password.split('').sort(() => Math.random() - 0.5).join('');
  }

  // Generate session ID
  static generateSessionId(): string {
    return `sess_${Date.now()}_${this.random(16)}`;
  }

  // Generate API key
  static generateApiKey(prefix: string = 'sk_'): string {
    return `${prefix}${this.random(32)}`;
  }

  // Generate secure random bytes as hex
  static secureRandomHex(bytes: number = 32): string {
    return crypto.randomBytes(bytes).toString('hex');
  }

  // Timing safe string comparison
  static timingSafeEqual(a: string, b: string): boolean {
    try {
      return crypto.timingSafeEqual(
        Buffer.from(a, 'utf8'),
        Buffer.from(b, 'utf8')
      );
    } catch {
      return false;
    }
  }
}