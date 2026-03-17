import { prismaWrite, prismaRead } from '../../lib/prisma';
import { hashPassword, verifyPassword, sha256, hashFingerprint } from '../../utils/hash';
import { signTokenPair, signLoginPendingToken } from '../../utils/jwt';
import { generateAccountNumber } from '../../utils/accountNumber';
import { createOtp } from '../../utils/otp';
import { sendMail, otpEmailHtml, newDeviceAlertHtml } from '../../lib/mailer';
import { publishEvent } from '../../lib/kafka';
import { config } from '../../config/env';
import { LiveRegisterInput, LiveLoginInput } from './live.schema';
import { AppError } from '../../utils/errors';

// ── Register ──────────────────────────────────────────────────────────────────

export async function registerLiveUser(input: LiveRegisterInput) {
  // Account number from Redis atomic counter
  const accountNumber = await generateAccountNumber('LU');
  const passwordHash = await hashPassword(input.password);

  // Publish to Kafka → user-service will:
  //   1. Check phone uniqueness across all accounts (block if same phone exists)
  //   2. Create the actual user row
  //   isSelfTrading is always true for self-registered users
  //   leverage is always 100 by default
  await publishEvent('user.register', accountNumber, {
    type: 'LIVE_USER_REGISTER',
    accountNumber,
    passwordHash,
    email: input.email,
    phoneNumber: input.phoneNumber,
    country: input.country,
    groupName: input.groupName,
    currency: 'USD',
    leverage: 100,
    isSelfTrading: true,
  });

  // Send email verification OTP
  const otp = await createOtp(input.email, 'email_verify');
  await sendMail({
    to: input.email,
    subject: 'Verify your LiveFXHub account',
    html: otpEmailHtml(otp, 'email verification', config.otpExpiresInMinutes),
  });

  return { accountNumber, message: 'Account created. Please verify your email.' };
}

// ── Login ─────────────────────────────────────────────────────────────────────

interface LoginContext {
  userId: string;
  userType: 'live';
  accountNumber: string;
  groupName: string;
  currency: string;
  passwordHash: string;
  isActive: boolean;
}

/**
 * Fetches live user context from user-service via internal HTTP call.
 * In dev, we can also pass a resolved context directly.
 */
async function getLiveUserContext(email: string): Promise<LoginContext | null> {
  try {
    const resp = await fetch(`${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/by-email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-service-secret': config.internalSecret,
      },
      body: JSON.stringify({ email, userType: 'live' }),
    });
    if (!resp.ok) return null;
    return (await resp.json()) as LoginContext;
  } catch {
    return null;
  }
}

export async function loginLiveUser(
  input: LiveLoginInput,
  ipAddress: string,
  userAgent: string,
) {
  // Fetch user from user-service
  const ctx = await getLiveUserContext(input.email);
  if (!ctx) throw new AppError('INVALID_CREDENTIALS', 401);
  if (!ctx.isActive) throw new AppError('ACCOUNT_INACTIVE', 403);

  // Verify password
  const passwordOk = await verifyPassword(input.password, ctx.passwordHash);
  if (!passwordOk) throw new AppError('INVALID_CREDENTIALS', 401);

  const fingerprintHash = input.deviceFingerprint
    ? hashFingerprint(input.deviceFingerprint)
    : null;

  // ── Device check ──────────────────────────────────────────────────────────
  let requires2FA = false;
  let isNewDevice = false;

  if (fingerprintHash) {
    const knownDevice = await prismaRead.knownDevice.findUnique({
      where: { userId_userType_fingerprintHash: {
        userId: ctx.userId,
        userType: 'live',
        fingerprintHash,
      }},
    });

    if (!knownDevice) {
      // Brand new device
      isNewDevice = true;
      requires2FA = true;
    } else {
      // Known device — check inactivity
      const daysSinceLastSeen = (Date.now() - knownDevice.lastSeenAt.getTime()) / 86_400_000;
      if (daysSinceLastSeen > config.inactivity2faDays) {
        requires2FA = true;
      }
    }
  }

  // ── If 2FA required, return login_pending token ───────────────────────────
  if (requires2FA) {
    // Check if user has TOTP set up
    const totpRecord = await prismaRead.userTotpSecret.findUnique({
      where: { userId_userType: { userId: ctx.userId, userType: 'live' } },
    });
    const hasTOTP = totpRecord?.isVerified ?? false;

    const loginToken = signLoginPendingToken(ctx.userId, 'live');

    if (!hasTOTP) {
      // Send OTP to email
      const otp = await createOtp(ctx.userId, 'login');
      await sendMail({
        to: input.email,
        subject: 'Your LiveFXHub login code',
        html: otpEmailHtml(otp, 'login verification', config.otpExpiresInMinutes),
      });
    }

    // New device — send alert email async (non-blocking)
    if (isNewDevice && config.newDeviceAlert) {
      sendMail({
        to: input.email,
        subject: '⚠️ New device login detected — LiveFXHub',
        html: newDeviceAlertHtml(
          input.deviceLabel ?? userAgent,
          ipAddress,
          new Date().toISOString(),
        ),
      }).catch(() => void 0);
    }

    return {
      status: hasTOTP ? 'totp_required' : 'otp_required',
      loginToken,
      message: hasTOTP
        ? 'Enter your authenticator code to continue'
        : 'A verification code has been sent to your email',
    };
  }

  // ── Issue tokens directly ─────────────────────────────────────────────────
  return await issueTokensAndCreateSession(ctx, fingerprintHash, input.deviceLabel ?? null, ipAddress, userAgent, isNewDevice);
}

export async function issueTokensAndCreateSession(
  ctx: LoginContext,
  fingerprintHash: string | null,
  deviceLabel: string | null,
  ipAddress: string,
  userAgent: string,
  isNewDevice: boolean,
) {
  const tokens = signTokenPair(ctx.userId, ctx.userType, ctx.accountNumber, {
    groupName: ctx.groupName,
    currency: ctx.currency,
  });

  // Create session row
  await prismaWrite.session.create({
    data: {
      id: tokens.sessionId,
      userId: ctx.userId,
      userType: 'live',
      tokenHash: sha256(tokens.accessJti),
      refreshHash: sha256(tokens.refreshJti),
      expiresAt: tokens.refreshExpiresAt,
      ipAddress,
      userAgent,
      fingerprintHash,
    },
  });

  // Upsert known_devices if fingerprint present
  if (fingerprintHash) {
    await prismaWrite.knownDevice.upsert({
      where: { userId_userType_fingerprintHash: { userId: ctx.userId, userType: 'live', fingerprintHash }},
      create: { userId: ctx.userId, userType: 'live', fingerprintHash, label: deviceLabel },
      update: { lastSeenAt: new Date() },
    });
  }

  // Kafka journal event
  await publishEvent('user.journal.events', ctx.userId, {
    eventType: isNewDevice ? 'NEW_DEVICE_LOGIN' : 'LOGIN_SUCCESS',
    userId: ctx.userId,
    userType: 'live',
    ipAddress,
  });

  return {
    status: 'success',
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    expiresIn: 15 * 60,
    tokenType: 'Bearer',
    sessionId: tokens.sessionId,
  };
}
