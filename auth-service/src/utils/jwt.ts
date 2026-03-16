import jwt, { SignOptions } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config/env';

export interface JwtPayload {
  jti: string;
  sub: string;     // user UUID
  sid: string;     // session UUID
  typ: 'access' | 'refresh' | 'login_pending';
  userType: string;
  accountNumber: string;
  groupName?: string;
  currency?: string;
  permissions?: string[];
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  accessJti: string;
  refreshJti: string;
  accessExpiresAt: Date;
  refreshExpiresAt: Date;
}

function msFromExpiry(expiry: string): number {
  const match = expiry.match(/^(\d+)([smhd])$/);
  if (!match) return 15 * 60 * 1000;
  const val = parseInt(match[1]!);
  const unit = match[2]!;
  const multiplier = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[unit] ?? 60_000;
  return val * multiplier;
}

export function signTokenPair(
  userId: string,
  userType: string,
  accountNumber: string,
  extras: Partial<Pick<JwtPayload, 'groupName' | 'currency' | 'permissions'>> = {},
  existingSessionId?: string,
): TokenPair {
  const sessionId = existingSessionId ?? uuidv4();
  const accessJti = uuidv4();
  const refreshJti = uuidv4();

  const common = { sub: userId, sid: sessionId, userType, accountNumber, ...extras };

  const access = jwt.sign(
    { ...common, jti: accessJti, typ: 'access' } as object,
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn, issuer: 'livefxhub-auth', audience: 'livefxhub-api' } as SignOptions,
  );

  const refresh = jwt.sign(
    { ...common, jti: refreshJti, typ: 'refresh' } as object,
    config.jwtSecret,
    { expiresIn: config.jwtRefreshExpiresIn, issuer: 'livefxhub-auth', audience: 'livefxhub-api' } as SignOptions,
  );

  const now = Date.now();
  return {
    accessToken: access,
    refreshToken: refresh,
    sessionId,
    accessJti,
    refreshJti,
    accessExpiresAt: new Date(now + msFromExpiry(config.jwtExpiresIn)),
    refreshExpiresAt: new Date(now + msFromExpiry(config.jwtRefreshExpiresIn)),
  };
}

export function signLoginPendingToken(userId: string, userType: string): string {
  return jwt.sign(
    { sub: userId, userType, typ: 'login_pending', jti: uuidv4() } as object,
    config.jwtSecret,
    { expiresIn: '5m', issuer: 'livefxhub-auth', audience: 'livefxhub-api' } as SignOptions,
  );
}

export function verifyToken(token: string): JwtPayload {
  return jwt.verify(token, config.jwtSecret, {
    issuer: 'livefxhub-auth',
    audience: 'livefxhub-api',
  }) as JwtPayload;
}
