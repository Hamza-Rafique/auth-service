// src/core/services/email.service.ts
import { logger } from '../utils/logger';

export interface EmailOptions {
  to: string | string[];
  subject: string;
  template: string;
  data: Record<string, any>;
  attachments?: Array<{
    filename: string;
    content: Buffer | string;
    contentType?: string;
  }>;
}

export class EmailService {
  // In production, integrate with SendGrid, AWS SES, etc.
  
  static async sendEmail(options: EmailOptions): Promise<boolean> {
    try {
      // Log email for development
      logger.info({
        type: 'EMAIL',
        to: Array.isArray(options.to) ? options.to : [options.to],
        subject: options.subject,
        template: options.template,
        data: options.data
      }, 'Email sent');

      // In development, just log the email
      if (process.env.NODE_ENV === 'development') {
        console.log('\n📧 Email Details:');
        console.log('To:', options.to);
        console.log('Subject:', options.subject);
        console.log('Template:', options.template);
        console.log('Data:', JSON.stringify(options.data, null, 2));
        console.log('---\n');
      }

      // In production, implement actual email sending
      // Example with SendGrid:
      /*
      const sgMail = require('@sendgrid/mail');
      sgMail.setApiKey(process.env.SENDGRID_API_KEY);
      
      const msg = {
        to: options.to,
        from: process.env.EMAIL_FROM,
        subject: options.subject,
        html: this.renderTemplate(options.template, options.data),
        attachments: options.attachments
      };
      
      await sgMail.send(msg);
      */

      return true;
    } catch (error) {
      logger.error({
        type: 'EMAIL_ERROR',
        error: error.message,
        options
      }, 'Failed to send email');
      
      return false;
    }
  }

  // Email templates
  static readonly templates = {
    VERIFICATION: 'verification',
    PASSWORD_RESET: 'password-reset',
    WELCOME: 'welcome',
    PASSWORD_CHANGED: 'password-changed',
    ACCOUNT_LOCKED: 'account-locked',
    LOGIN_ALERT: 'login-alert'
  };

  // Send verification email
  static async sendVerificationEmail(
    email: string,
    token: string,
    name?: string
  ): Promise<boolean> {
    const verificationLink = `${process.env.APP_URL}/verify-email?token=${token}`;
    
    return this.sendEmail({
      to: email,
      subject: 'Verify Your Email Address',
      template: this.templates.VERIFICATION,
      data: {
        name: name || 'User',
        verificationLink,
        appName: process.env.APP_NAME || 'Our App'
      }
    });
  }

  // Send password reset email
  static async sendPasswordResetEmail(
    email: string,
    token: string,
    name?: string
  ): Promise<boolean> {
    const resetLink = `${process.env.APP_URL}/reset-password?token=${token}`;
    
    return this.sendEmail({
      to: email,
      subject: 'Reset Your Password',
      template: this.templates.PASSWORD_RESET,
      data: {
        name: name || 'User',
        resetLink,
        expiryHours: 1, // Token expires in 1 hour
        appName: process.env.APP_NAME || 'Our App'
      }
    });
  }

  // Send password changed notification
  static async sendPasswordChangedNotification(
    email: string,
    name?: string
  ): Promise<boolean> {
    return this.sendEmail({
      to: email,
      subject: 'Your Password Has Been Changed',
      template: this.templates.PASSWORD_CHANGED,
      data: {
        name: name || 'User',
        timestamp: new Date().toLocaleString(),
        ip: 'Unknown', // Would come from request context
        userAgent: 'Unknown', // Would come from request context
        appName: process.env.APP_NAME || 'Our App'
      }
    });
  }

  // Send welcome email
  static async sendWelcomeEmail(
    email: string,
    name?: string
  ): Promise<boolean> {
    return this.sendEmail({
      to: email,
      subject: 'Welcome to Our App!',
      template: this.templates.WELCOME,
      data: {
        name: name || 'User',
        appName: process.env.APP_NAME || 'Our App',
        loginLink: `${process.env.APP_URL}/login`,
        supportEmail: process.env.SUPPORT_EMAIL || 'support@example.com'
      }
    });
  }

  // Send login alert
  static async sendLoginAlert(
    email: string,
    deviceInfo: string,
    ip: string,
    location?: string,
    timestamp?: Date
  ): Promise<boolean> {
    return this.sendEmail({
      to: email,
      subject: 'New Login Detected',
      template: this.templates.LOGIN_ALERT,
      data: {
        device: deviceInfo || 'Unknown Device',
        ip,
        location: location || 'Unknown Location',
        timestamp: (timestamp || new Date()).toLocaleString(),
        changePasswordLink: `${process.env.APP_URL}/change-password`,
        supportEmail: process.env.SUPPORT_EMAIL || 'support@example.com'
      }
    });
  }

  // Private method to render email templates
  private static renderTemplate(template: string, data: any): string {
    // In production, use a template engine like Handlebars
    // For now, return simple HTML
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${data.subject || 'Email'}</title>
      </head>
      <body>
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2>${data.subject || 'Notification'}</h2>
          <pre>${JSON.stringify(data, null, 2)}</pre>
        </div>
      </body>
      </html>
    `;
  }
}