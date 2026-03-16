import { prismaWrite, prismaRead } from '../../lib/prisma';
import { hashPassword, sha256 } from '../../utils/hash';
import { AppError } from '../../utils/errors';
import { sendMail, otpEmailHtml } from '../../lib/mailer';
import { createOtp, verifyOtpCode } from '../../utils/otp';
import { config } from '../../config/env';
import { randomBytes } from 'crypto';
import { UserType } from '@prisma/client';

/** Step 1: User provides email → OTP sent (combined with auth/otp/send) */
export async function requestPasswordReset(email: string, _userType: 'live' | 'demo') {
  // Always respond success (prevents user enumeration)
  const otp = await createOtp(email, 'forgot_password');
  await sendMail({
    to: email,
    subject: 'Reset your LiveFXHub password',
    html: otpEmailHtml(otp, 'password reset', config.otpExpiresInMinutes),
  });
}

/** Step 2: User verifies OTP → gets a short-lived reset token */
export async function verifyResetOtp(
  email: string,
  _userType: 'live' | 'demo',
  otp: string,
  userId: string,
) {
  const result = await verifyOtpCode(email, 'forgot_password', otp);
  if (!result.success) throw new AppError(result.reason ?? 'INVALID_OTP', 400);

  // Issue a one-time reset token
  const rawToken = randomBytes(32).toString('hex');
  const tokenHash = sha256(rawToken);

  await prismaWrite.passwordResetToken.create({
    data: {
      userId,
      userType: _userType as UserType,
      tokenHash,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 min
    },
  });

  return { resetToken: rawToken };
}

/** Step 3: User provides reset token + new password */
export async function resetPassword(
  resetToken: string,
  newPassword: string,
) {
  const tokenHash = sha256(resetToken);
  const record = await prismaRead.passwordResetToken.findUnique({ where: { tokenHash } });

  if (!record || record.usedAt || record.expiresAt < new Date()) {
    throw new AppError('INVALID_OR_EXPIRED_RESET_TOKEN', 400);
  }

  const passwordHash = await hashPassword(newPassword);

  // Tell user-service to update the password
  await fetch(`${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/${record.userId}/password`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', 'x-service-secret': config.internalSecret },
    body: JSON.stringify({ passwordHash, userType: record.userType }),
  });

  // Mark token used
  await prismaWrite.passwordResetToken.update({
    where: { tokenHash },
    data: { usedAt: new Date() },
  });

  // Revoke all existing sessions on password change
  await prismaWrite.session.updateMany({
    where: { userId: record.userId, userType: record.userType, revokedAt: null },
    data: { revokedAt: new Date() },
  });

  return { message: 'Password reset successfully. Please log in with your new password.' };
}

/** Regenerate view-only password (read-only MT-style investor login) */
export async function regenerateViewPassword(userId: string, userType: string) {
  const viewPassword = randomBytes(6).toString('base64').slice(0, 8).toUpperCase();

  await fetch(`${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/${userId}/view-password`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', 'x-service-secret': config.internalSecret },
    body: JSON.stringify({ viewPassword, userType }),
  });

  return { viewPassword, message: 'View password regenerated. This is shown only once.' };
}
