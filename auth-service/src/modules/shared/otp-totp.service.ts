import { prismaWrite, prismaRead } from '../../lib/prisma';
import { createOtp } from '../../utils/otp';
import { generateTotpSetup, verifyTotpCode } from '../../utils/totp';
import { sendMail, otpEmailHtml } from '../../lib/mailer';
import { AppError } from '../../utils/errors';
import { config } from '../../config/env';
import { UserType } from '@prisma/client';

// ── OTP send (login gate / email verify / withdrawal confirm / etc.) ──────────
export async function sendOtp(
  identifier: string,  // email address
  purpose: string,
) {
  const otp = await createOtp(identifier, purpose);
  await sendMail({
    to: identifier,
    subject: 'Your LiveFXHub verification code',
    html: otpEmailHtml(otp, purpose.replace(/_/g, ' '), config.otpExpiresInMinutes),
  });
}

// ── TOTP setup ────────────────────────────────────────────────────────────────
export async function setupTotp(userId: string, userType: string, email: string) {
  const { secretEnc, otpauthUrl } = generateTotpSetup(email);

  // Save unverified TOTP secret (overwrites any previous unverified setup)
  await prismaWrite.userTotpSecret.upsert({
    where: { userId_userType: { userId, userType: userType as UserType } },
    create: { userId, userType: userType as UserType, secretEnc, isVerified: false },
    update: { secretEnc, isVerified: false, disabledAt: null, enabledAt: null },
  });

  return { otpauthUrl, message: 'Scan the QR code with your authenticator app, then call /totp/confirm' };
}

// ── TOTP confirm (first code after setup) ─────────────────────────────────────
export async function confirmTotp(userId: string, userType: string, code: string) {
  const record = await prismaRead.userTotpSecret.findUnique({
    where: { userId_userType: { userId, userType: userType as UserType } },
  });
  if (!record) throw new AppError('TOTP_NOT_SETUP', 400);
  if (record.isVerified) throw new AppError('TOTP_ALREADY_VERIFIED', 400);

  const valid = verifyTotpCode(record.secretEnc, code);
  if (!valid) throw new AppError('INVALID_TOTP_CODE', 400);

  await prismaWrite.userTotpSecret.update({
    where: { userId_userType: { userId, userType: userType as UserType } },
    data: { isVerified: true, enabledAt: new Date() },
  });

  return { message: '2FA has been enabled on your account' };
}

// ── TOTP verify at login gate ─────────────────────────────────────────────────
export async function verifyTotpAtLogin(
  userId: string,
  userType: string,
  code: string,
) {
  const record = await prismaRead.userTotpSecret.findUnique({
    where: { userId_userType: { userId, userType: userType as UserType } },
  });
  if (!record?.isVerified) throw new AppError('TOTP_NOT_ENABLED', 400);

  const valid = verifyTotpCode(record.secretEnc, code);
  if (!valid) throw new AppError('INVALID_TOTP_CODE', 400);
}

// ── TOTP disable ──────────────────────────────────────────────────────────────
export async function disableTotp(userId: string, userType: string, code: string) {
  const record = await prismaRead.userTotpSecret.findUnique({
    where: { userId_userType: { userId, userType: userType as UserType } },
  });
  if (!record?.isVerified) throw new AppError('TOTP_NOT_ENABLED', 400);

  const valid = verifyTotpCode(record.secretEnc, code);
  if (!valid) throw new AppError('INVALID_TOTP_CODE', 400);

  await prismaWrite.userTotpSecret.update({
    where: { userId_userType: { userId, userType: userType as UserType } },
    data: { isVerified: false, disabledAt: new Date() },
  });

  return { message: '2FA has been disabled' };
}
