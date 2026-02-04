export class DateUtil {
  // Get current timestamp
  static now(): Date {
    return new Date();
  }

  // Get ISO string
  static isoString(): string {
    return new Date().toISOString();
  }

  // Format date
  static format(date: Date, format: string = 'YYYY-MM-DD HH:mm:ss'): string {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');

    return format
      .replace('YYYY', String(year))
      .replace('MM', month)
      .replace('DD', day)
      .replace('HH', hours)
      .replace('mm', minutes)
      .replace('ss', seconds);
  }

  // Add days to date
  static addDays(date: Date, days: number): Date {
    const result = new Date(date);
    result.setDate(result.getDate() + days);
    return result;
  }

  // Add minutes to date
  static addMinutes(date: Date, minutes: number): Date {
    const result = new Date(date);
    result.setMinutes(result.getMinutes() + minutes);
    return result;
  }

  // Add hours to date
  static addHours(date: Date, hours: number): Date {
    const result = new Date(date);
    result.setHours(result.getHours() + hours);
    return result;
  }

  // Check if date is expired
  static isExpired(date: Date): boolean {
    return date < new Date();
  }

  // Get difference in minutes
  static diffInMinutes(date1: Date, date2: Date): number {
    return Math.floor((date2.getTime() - date1.getTime()) / (1000 * 60));
  }

  // Get difference in days
  static diffInDays(date1: Date, date2: Date): number {
    return Math.floor((date2.getTime() - date1.getTime()) / (1000 * 60 * 60 * 24));
  }

  // Parse date string
  static parse(dateString: string): Date | null {
    const date = new Date(dateString);
    return isNaN(date.getTime()) ? null : date;
  }

  // Generate expiry date for tokens
  static generateExpiry(minutes: number = 15): Date {
    return this.addMinutes(new Date(), minutes);
  }

  // Generate refresh token expiry
  static generateRefreshExpiry(days: number = 7): Date {
    return this.addDays(new Date(), days);
  }

  // Check if date is within range
  static isWithinRange(
    date: Date,
    start: Date,
    end: Date,
    inclusive: boolean = true
  ): boolean {
    if (inclusive) {
      return date >= start && date <= end;
    }
    return date > start && date < end;
  }

  // Get start of day
  static startOfDay(date: Date): Date {
    const result = new Date(date);
    result.setHours(0, 0, 0, 0);
    return result;
  }

  // Get end of day
  static endOfDay(date: Date): Date {
    const result = new Date(date);
    result.setHours(23, 59, 59, 999);
    return result;
  }

  // Get start of month
  static startOfMonth(date: Date): Date {
    const result = new Date(date);
    result.setDate(1);
    result.setHours(0, 0, 0, 0);
    return result;
  }

  // Get end of month
  static endOfMonth(date: Date): Date {
    const result = new Date(date);
    result.setMonth(result.getMonth() + 1);
    result.setDate(0);
    result.setHours(23, 59, 59, 999);
    return result;
  }

  // Convert to UTC
  static toUTC(date: Date): Date {
    return new Date(date.toUTCString());
  }

  // Convert from UTC string
  static fromUTCString(utcString: string): Date {
    return new Date(utcString);
  }

  // Get human readable time difference
  static timeAgo(date: Date): string {
    const now = new Date();
    const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);

    let interval = Math.floor(seconds / 31536000);
    if (interval >= 1) {
      return interval === 1 ? '1 year ago' : `${interval} years ago`;
    }
    
    interval = Math.floor(seconds / 2592000);
    if (interval >= 1) {
      return interval === 1 ? '1 month ago' : `${interval} months ago`;
    }
    
    interval = Math.floor(seconds / 86400);
    if (interval >= 1) {
      return interval === 1 ? '1 day ago' : `${interval} days ago`;
    }
    
    interval = Math.floor(seconds / 3600);
    if (interval >= 1) {
      return interval === 1 ? '1 hour ago' : `${interval} hours ago`;
    }
    
    interval = Math.floor(seconds / 60);
    if (interval >= 1) {
      return interval === 1 ? '1 minute ago' : `${interval} minutes ago`;
    }
    
    return seconds <= 10 ? 'just now' : `${seconds} seconds ago`;
  }
}