import { prismaWrite } from '../../lib/prisma';
import { hashPassword, verifyPassword, sha256 } from '../../utils/hash';
import { signTokenPair } from '../../utils/jwt';
import { generateAccountNumber } from '../../utils/accountNumber';
import { publishEvent } from '../../lib/kafka';
import { AppError } from '../../utils/errors';
import { DemoRegisterInput, DemoLoginInput } from './demo.schema';
import { config } from '../../config/env';

export async function registerDemoUser(input: DemoRegisterInput) {
  const accountNumber = await generateAccountNumber('DU');
  const passwordHash = await hashPassword(input.password);

  await publishEvent('user.register', accountNumber, {
    type: 'DEMO_USER_REGISTER',
    accountNumber,
    passwordHash,
    email: input.email,
    name: input.name,
    phoneNumber: input.phoneNumber,
    country: input.country,
    city: input.city,
    state: input.state ?? null,
    groupName: input.groupName,
    currency: input.currency,
    leverage: input.leverage,
    initialBalance: input.initialBalance,
  });

  return { accountNumber, message: 'Demo account created successfully.' };
}

export async function loginDemoUser(
  input: DemoLoginInput,
  ipAddress: string,
  userAgent: string,
) {
  // Fetch demo user from user-service
  const resp = await fetch(`${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/by-email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-service-secret': config.internalSecret },
    body: JSON.stringify({ email: input.email, userType: 'demo' }),
  });

  if (!resp.ok) throw new AppError('INVALID_CREDENTIALS', 401);

  const ctx = await resp.json() as {
    userId: string; accountNumber: string; groupName: string;
    currency: string; passwordHash: string; isActive: boolean;
  };

  if (!ctx.isActive) throw new AppError('ACCOUNT_INACTIVE', 403);
  const ok = await verifyPassword(input.password, ctx.passwordHash);
  if (!ok) throw new AppError('INVALID_CREDENTIALS', 401);

  // Demo users — no 2FA, issue tokens directly
  const tokens = signTokenPair(ctx.userId, 'demo', ctx.accountNumber, {
    groupName: ctx.groupName,
    currency: ctx.currency,
  });

  await prismaWrite.session.create({
    data: {
      id: tokens.sessionId,
      userId: ctx.userId,
      userType: 'demo',
      tokenHash: sha256(tokens.accessJti),
      refreshHash: sha256(tokens.refreshJti),
      expiresAt: tokens.refreshExpiresAt,
      ipAddress,
      userAgent,
    },
  });

  await publishEvent('user.journal.events', ctx.userId, {
    eventType: 'LOGIN_SUCCESS',
    userId: ctx.userId,
    userType: 'demo',
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
