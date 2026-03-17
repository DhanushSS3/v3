import { prismaWrite, prismaRead } from '../../lib/prisma';
import { logger } from '../../lib/logger';

// ── Types ──────────────────────────────────────────────────────────────────────

interface LiveRegisterEvent {
  accountNumber: string;
  passwordHash:  string;
  email:         string;
  phoneNumber:   string;
  country:       string;
  groupName:     string;
  currency:      string;
  leverage:      number;
  isSelfTrading: boolean;
  [key: string]: unknown;
}

interface DemoRegisterEvent {
  accountNumber:  string;
  passwordHash:   string;
  email:          string;
  groupName:      string;
  currency:       string;
  leverage:       number;
  initialBalance: number;
  [key: string]: unknown;
}

// ── Register from Kafka ───────────────────────────────────────────────────────

/**
 * Called by the Kafka consumer when LIVE_USER_REGISTER is received.
 *
 * Business rules enforced here:
 *   1. Same email  → allowed (multiple accounts per email is OK)
 *   2. Same phone  → REJECTED (phone must be globally unique)
 *      If rejected, we log the error (auth-service OTP was already sent, so
 *      the Kafka consumer just skips. The registration endpoint should ideally
 *      do a pre-flight phone check via the internal endpoint below — see
 *      /internal/users/check-phone)
 */
export async function registerLiveUserFromKafka(event: unknown): Promise<void> {
  const e = event as LiveRegisterEvent;

  // Phone uniqueness — this is the authoritative check
  const phoneTaken = await prismaRead.liveUser.findUnique({ where: { phone: e.phoneNumber } });
  if (phoneTaken) {
    logger.warn(
      { accountNumber: e.accountNumber, phone: e.phoneNumber },
      'LIVE_USER_REGISTER rejected: phone already registered to another account',
    );
    // TODO: publish user.register.failed event so auth-service can send error email
    return;
  }

  await prismaWrite.liveUser.create({
    data: {
      accountNumber: e.accountNumber,
      email:         e.email,
      phone:         e.phoneNumber,
      passwordHash:  e.passwordHash,
      countryCode:   e.country,
      groupName:     e.groupName,
      currency:      e.currency,
      leverage:      e.leverage,
      isSelfTrading: e.isSelfTrading,
      isActive:      true,
      isVerified:    false,
    },
  });

  logger.info({ accountNumber: e.accountNumber, email: e.email }, 'Live user registered');
}

export async function registerDemoUserFromKafka(event: unknown): Promise<void> {
  const e = event as DemoRegisterEvent;

  await prismaWrite.demoUser.create({
    data: {
      accountNumber: e.accountNumber,
      email:         e.email,
      passwordHash:  e.passwordHash,
      fullName:      null,
      groupName:     e.groupName,
      currency:      e.currency,
      leverage:      e.leverage,
      demoBalance:   e.initialBalance ?? 10000,
      isActive:      true,
    },
  });

  logger.info({ accountNumber: e.accountNumber }, 'Demo user registered');
}

// ── Internal API helpers (called by internal routes) ─────────────────────────

export interface UserAuthContext {
  userId:        string;
  accountNumber: string;
  groupName:     string;
  currency:      string;
  passwordHash:  string;
  isActive:      boolean;
  userType:      'live' | 'demo';
}

// Find live user by email — returns ALL accounts for that email (for login selector)
export async function getLiveUsersByEmail(email: string): Promise<UserAuthContext[]> {
  const users = await prismaRead.liveUser.findMany({
    where: { email },
    select: {
      id: true, accountNumber: true, groupName: true,
      currency: true, passwordHash: true, isActive: true,
    },
  });
  return users.map((u) => ({ ...u, userId: u.id, userType: 'live' as const }));
}

// When user has only one account, we return it directly (99% case)
export async function getLiveUserByEmail(email: string): Promise<UserAuthContext | null> {
  const user = await prismaRead.liveUser.findFirst({
    where: { email, isActive: true },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true, accountNumber: true, groupName: true,
      currency: true, passwordHash: true, isActive: true,
    },
  });
  if (!user) return null;
  return { ...user, userId: user.id, userType: 'live' };
}

export async function getDemoUserByEmail(email: string): Promise<UserAuthContext | null> {
  const user = await prismaRead.demoUser.findFirst({
    where: { email, isActive: true },
    select: {
      id: true, accountNumber: true, groupName: true,
      currency: true, passwordHash: true, isActive: true,
    },
  });
  if (!user) return null;
  return { ...user, userId: user.id, userType: 'demo' };
}

export async function getUserById(userId: string, userType: string): Promise<UserAuthContext | null> {
  if (userType === 'live') {
    const user = await prismaRead.liveUser.findUnique({
      where: { id: userId },
      select: {
        id: true, accountNumber: true, groupName: true,
        currency: true, passwordHash: true, isActive: true,
      },
    });
    if (!user) return null;
    return { ...user, userId: user.id, userType: 'live' };
  }

  const user = await prismaRead.demoUser.findUnique({
    where: { id: userId },
    select: {
      id: true, accountNumber: true, groupName: true,
      currency: true, passwordHash: true, isActive: true,
    },
  });
  if (!user) return null;
  return { ...user, userId: user.id, userType: 'demo' };
}

export async function isPhoneAvailable(phone: string): Promise<boolean> {
  const count = await prismaRead.liveUser.count({ where: { phone } });
  return count === 0;
}

// Update password (called by auth-service after password reset)
export async function updateUserPassword(
  userId: string, userType: string, passwordHash: string,
): Promise<void> {
  if (userType === 'live') {
    await prismaWrite.liveUser.update({
      where: { id: userId },
      data: { passwordHash },
    });
  } else {
    await prismaWrite.demoUser.update({
      where: { id: userId },
      data: { passwordHash },
    });
  }
}

// Update view-only password hash
export async function updateViewPassword(
  userId: string, viewPassword: string,
): Promise<void> {
  // bcrypt hash done by caller (auth-service) or here
  await prismaWrite.userTradingConfig.upsert({
    where:  { userId },
    create: { userId, viewPasswordHash: viewPassword },
    update: { viewPasswordHash: viewPassword },
  });
}

// Mark email verified
export async function markEmailVerified(userId: string): Promise<void> {
  await prismaWrite.liveUser.update({
    where: { id: userId },
    data:  { isVerified: true },
  });
}

// Update lastLoginAt (called by auth-service after successful login)
export async function touchLastLogin(userId: string, userType: string): Promise<void> {
  const now = new Date();
  if (userType === 'live') {
    await prismaWrite.liveUser.update({ where: { id: userId }, data: { lastLoginAt: now } });
  } else {
    await prismaWrite.demoUser.update({ where: { id: userId }, data: { lastLoginAt: now } });
  }
}
