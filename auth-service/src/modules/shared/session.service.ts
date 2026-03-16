import { prismaWrite, prismaRead } from '../../lib/prisma';
import { verifyToken, signTokenPair } from '../../utils/jwt';
import { sha256 } from '../../utils/hash';
import { AppError } from '../../utils/errors';
import { UserType } from '@prisma/client';

// ── Refresh token ─────────────────────────────────────────────────────────────
export async function refreshSession(refreshToken: string, ipAddress: string, userAgent: string) {
  let payload: ReturnType<typeof verifyToken>;
  try {
    payload = verifyToken(refreshToken);
  } catch {
    throw new AppError('INVALID_REFRESH_TOKEN', 401);
  }

  if (payload.typ !== 'refresh') throw new AppError('INVALID_TOKEN_TYPE', 401);

  // Validate refresh session in DB
  const refreshHash = sha256(payload.jti);
  const session = await prismaRead.session.findUnique({ where: { refreshHash } });
  if (!session || session.revokedAt || session.expiresAt < new Date()) {
    throw new AppError('SESSION_NOT_FOUND_OR_EXPIRED', 401);
  }

  // Rotate: revoke old session, create new one
  await prismaWrite.session.update({
    where: { id: session.id },
    data: { revokedAt: new Date() },
  });

  const extras: Partial<Pick<import('../../utils/jwt').JwtPayload, 'groupName' | 'currency' | 'permissions'>> = {};
  if (payload.groupName  !== undefined) extras.groupName  = payload.groupName;
  if (payload.currency   !== undefined) extras.currency   = payload.currency;
  if (payload.permissions !== undefined) extras.permissions = payload.permissions;

  const tokens = signTokenPair(
    payload.sub,
    payload.userType,
    payload.accountNumber,
    extras,
    session.id, // Same session context
  );

  await prismaWrite.session.create({
    data: {
      id: tokens.sessionId,
      userId: payload.sub,
      userType: payload.userType as UserType,
      tokenHash: sha256(tokens.accessJti),
      refreshHash: sha256(tokens.refreshJti),
      expiresAt: tokens.refreshExpiresAt,
      ipAddress,
      userAgent,
      fingerprintHash: session.fingerprintHash,
    },
  });

  return {
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    expiresIn: 15 * 60,
    tokenType: 'Bearer',
  };
}

// ── Logout ────────────────────────────────────────────────────────────────────
export async function logoutSession(sessionId: string) {
  await prismaWrite.session.updateMany({
    where: { id: sessionId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

export async function logoutAllSessions(userId: string, userType: string) {
  await prismaWrite.session.updateMany({
    where: { userId, userType: userType as UserType, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

// ── List sessions ─────────────────────────────────────────────────────────────
export async function listSessions(userId: string, userType: string) {
  return prismaRead.session.findMany({
    where: { userId, userType: userType as UserType, revokedAt: null, expiresAt: { gt: new Date() } },
    select: {
      id: true, issuedAt: true, expiresAt: true, ipAddress: true, userAgent: true,
      deviceId: true,
    },
    orderBy: { issuedAt: 'desc' },
  });
}
