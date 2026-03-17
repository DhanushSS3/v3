import { prismaWrite } from '../../lib/prisma';
import { verifyPassword, sha256 } from '../../utils/hash';
import { signTokenPair } from '../../utils/jwt';
import { createOtp, verifyOtpCode } from '../../utils/otp';
import { verifyTotpCode } from '../../utils/totp';
import { prismaRead } from '../../lib/prisma';
import { sendMail, otpEmailHtml } from '../../lib/mailer';
import { publishEvent } from '../../lib/kafka';
import { AppError } from '../../utils/errors';
import { config } from '../../config/env';
import { UserType } from '@prisma/client';

// ── Step 1: password verify → OTP or TOTP path ───────────────────────────────
export async function adminLoginStep1(email: string, password: string) {
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

  // Check if admin has TOTP set up
  const totpRecord = await prismaRead.userTotpSecret.findUnique({
    where: { userId_userType: { userId: admin.id, userType: 'admin' } },
  });
  const hasTOTP = totpRecord?.isVerified ?? false;

  if (!hasTOTP) {
    // No TOTP — send email OTP
    const otp = await createOtp(email, 'login');
    await sendMail({
      to: email,
      subject: 'Your LiveFXHub admin login code',
      html: otpEmailHtml(otp, 'admin login', config.otpExpiresInMinutes),
    });
  }

  return {
    adminId: admin.id,
    method: hasTOTP ? 'totp' : 'email_otp',
    message: hasTOTP
      ? 'Enter your authenticator app code to continue'
      : 'OTP has been sent to your email',
  };
}

// ── Step 2: verify OTP or TOTP → issue tokens ─────────────────────────────────
export async function adminLoginStep2(
  adminId: string,
  email: string,
  code: string, // either 6-digit OTP or 6-digit TOTP
  ipAddress: string,
  userAgent: string,
) {
  let verified = false;

  // Try TOTP first
  const totpRecord = await prismaRead.userTotpSecret.findUnique({
    where: { userId_userType: { userId: adminId, userType: 'admin' } },
  });

  if (totpRecord?.isVerified) {
    verified = verifyTotpCode(totpRecord.secretEnc, code);
    if (!verified) throw new AppError('INVALID_TOTP_CODE', 400);
  } else {
    // Fall back to email OTP
    const result = await verifyOtpCode(email, 'login', code);
    if (!result.success) throw new AppError(result.reason ?? 'INVALID_OTP', 400);
    verified = true;
  }

  // Fetch admin permissions
  const permResp = await fetch(`${process.env.ADMIN_SERVICE_INTERNAL_URL}/internal/admins/${adminId}/permissions`, {
    headers: { 'x-service-secret': config.internalSecret },
  });
  const { permissions, accountNumber } = await permResp.json() as {
    permissions: string[]; accountNumber: string;
  };

  const tokens = signTokenPair(adminId, 'admin', accountNumber ?? 'ADMIN', { permissions });

  await prismaWrite.session.create({
    data: {
      id: tokens.sessionId,
      userId: adminId,
      userType: 'admin' as UserType,
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
