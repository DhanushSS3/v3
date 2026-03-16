import nodemailer, { Transporter } from 'nodemailer';
import { config } from '../config/env';
import { logger } from './logger';

let transporter: Transporter;

function getTransporter(): Transporter {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: config.emailHost,
      port: config.emailPort,
      secure: config.emailSecure,
      auth: { user: config.emailUser, pass: config.emailPass },
      tls: { rejectUnauthorized: false }, // Required for Hostinger
    });
  }
  return transporter;
}

interface MailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

export async function sendMail(options: MailOptions): Promise<void> {
  try {
    const t = getTransporter();
    await t.sendMail({
      from: config.emailFrom,
      to: options.to,
      subject: options.subject,
      html: options.html,
      text: options.text ?? options.html.replace(/<[^>]+>/g, ''),
    });
    logger.debug({ to: options.to, subject: options.subject }, 'Email sent');
  } catch (err) {
    logger.error({ err, to: options.to, subject: options.subject }, 'Failed to send email');
    throw err;
  }
}

// ── Email templates ───────────────────────────────────────────────────────────

export function otpEmailHtml(otp: string, purpose: string, expiryMinutes: number): string {
  return `
    <!DOCTYPE html>
    <html>
    <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
      <div style="max-width: 480px; margin: 0 auto; background: #fff; border-radius: 8px; padding: 32px;">
        <h2 style="color: #1a1a2e; margin-bottom: 8px;">LiveFXHub</h2>
        <p style="color: #555; margin-bottom: 24px;">Your verification code for <strong>${purpose}</strong>:</p>
        <div style="background: #f0f4ff; border-radius: 8px; padding: 24px; text-align: center; margin-bottom: 24px;">
          <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #1a1a2e;">${otp}</span>
        </div>
        <p style="color: #888; font-size: 13px;">This code expires in <strong>${expiryMinutes} minutes</strong>. Do not share it with anyone.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
        <p style="color: #aaa; font-size: 12px;">If you didn't request this, please ignore this email or contact support.</p>
      </div>
    </body>
    </html>
  `.trim();
}

export function newDeviceAlertHtml(deviceInfo: string, ipAddress: string, timestamp: string): string {
  return `
    <!DOCTYPE html>
    <html>
    <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
      <div style="max-width: 480px; margin: 0 auto; background: #fff; border-radius: 8px; padding: 32px;">
        <h2 style="color: #1a1a2e;">⚠️ New Device Login Detected</h2>
        <p style="color: #555;">Your LiveFXHub account was accessed from a new device:</p>
        <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
          <tr><td style="padding: 8px; color: #888; width: 120px;">Device</td><td style="padding: 8px; color: #333;"><strong>${deviceInfo}</strong></td></tr>
          <tr style="background:#f9f9f9"><td style="padding: 8px; color: #888;">IP Address</td><td style="padding: 8px; color: #333;"><strong>${ipAddress}</strong></td></tr>
          <tr><td style="padding: 8px; color: #888;">Time</td><td style="padding: 8px; color: #333;"><strong>${timestamp}</strong></td></tr>
        </table>
        <p style="color: #d32f2f; font-weight: bold;">If this wasn't you, please change your password immediately or contact support.</p>
      </div>
    </body>
    </html>
  `.trim();
}
