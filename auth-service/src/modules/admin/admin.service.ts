import { prismaWrite } from '../../lib/prisma';
import { verifyPassword, sha256 } from '../../utils/hash';
import { signTokenPair } from '../../utils/jwt';
import { createOtp, verifyOtpCode } from '../../utils/otp';
import { sendMail, otpEmailHtml } from '../../lib/mailer';
import { publishEvent } from '../../lib/kafka';
import { AppError } from '../../utils/errors';
import { config } from '../../config/env';

// ── Step 1: password verify → send OTP ───────────────────────────────────────
export async function adminLoginStep1(email: string, password: string) {
  // Fetch admin from admin-service
  const resp = await fetch(`${process.env.ADMIN_SERVICE_INTERNAL_URL}/internal/admins/by-email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-service-secret': config.internalSecret },
    body: JSON.stringify({ email }),
  });

  if (!resp.ok) throw new AppError('INVALID_CREDENTIALS', 401);
  const admin = await resp.json() as {
    id: string; email: string; passwordHash: string; isActive: boolean;
  };

  if (!admin.isActive) throw new AppError('ACCOUNT_INACTIVE', 403);

  const ok = await verifyPassword(password, admin.passwordHash);
  if (!ok) throw new AppError('INVALID_CREDENTIALS', 401);

  // Always send OTP to email (admin always requires OTP regardless of device)
  const otp = await createOtp(email, 'login');
  await sendMail({
    to: email,
    subject: 'Your LiveFXHub admin login code',
    html: otpEmailHtml(otp, 'admin login', config.otpExpiresInMinutes),
  });

  return { adminId: admin.id, message: 'OTP has been sent to your email' };
}

// ── Step 2: verify OTP → issue tokens ─────────────────────────────────────────
export async function adminLoginStep2(
  adminId: string,
  email: string,
  otp: string,
  ipAddress: string,
  userAgent: string,
) {
  const result = await verifyOtpCode(email, 'login', otp);
  if (!result.success) throw new AppError(result.reason ?? 'INVALID_OTP', 400);

  // Fetch admin permissions from admin-service
  const resp = await fetch(`${process.env.ADMIN_SERVICE_INTERNAL_URL}/internal/admins/${adminId}/permissions`, {
    headers: { 'x-service-secret': config.internalSecret },
  });
  const { permissions, accountNumber } = await resp.json() as {
    permissions: string[]; accountNumber: string;
  };

  const tokens = signTokenPair(adminId, 'admin', accountNumber ?? 'ADMIN', {
    permissions,
  });

  await prismaWrite.session.create({
    data: {
      id: tokens.sessionId,
      userId: adminId,
      userType: 'admin',
      tokenHash: sha256(tokens.accessJti),
      refreshHash: sha256(tokens.refreshJti),
      expiresAt: tokens.refreshExpiresAt,
      ipAddress,
      userAgent,
    },
  });

  await publishEvent('user.journal.events', adminId, {
    eventType: 'ADMIN_LOGIN_SUCCESS',
    userId: adminId,
    userType: 'admin',
    ipAddress,
  });

  return {
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    expiresIn: 15 * 60,
    tokenType: 'Bearer',
  };
}
