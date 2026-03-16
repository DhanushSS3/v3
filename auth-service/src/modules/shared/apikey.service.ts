import { prismaWrite, prismaRead } from '../../lib/prisma';
import { sha256 } from '../../utils/hash';
import { AppError } from '../../utils/errors';
import { randomBytes } from 'crypto';
import { UserType } from '@prisma/client';

// ── Create API key ─────────────────────────────────────────────────────────────
export async function createApiKey(
  userId: string,
  userType: string,
  label: string,
  permissions: string[],
  expiresInDays?: number,
) {
  // Count existing active keys (limit to 10 per user)
  const count = await prismaRead.apiKey.count({
    where: { userId, userType: userType as UserType, revokedAt: null },
  });
  if (count >= 10) throw new AppError('API_KEY_LIMIT_REACHED', 400);

  // Generate raw key — shown to user once, never stored
  const rawKey = `lfx_${randomBytes(32).toString('hex')}`;
  const keyHash = sha256(rawKey);

  const expiresAt = expiresInDays
    ? new Date(Date.now() + expiresInDays * 86_400_000)
    : null;

  const key = await prismaWrite.apiKey.create({
    data: {
      userId,
      userType: userType as UserType,
      keyHash,
      label,
      permissions,
      expiresAt,
    },
    select: { id: true, label: true, permissions: true, createdAt: true, expiresAt: true },
  });

  return { ...key, key: rawKey, warning: 'Store this key securely — it will never be shown again.' };
}

// ── List API keys ──────────────────────────────────────────────────────────────
export async function listApiKeys(userId: string, userType: string) {
  return prismaRead.apiKey.findMany({
    where: { userId, userType: userType as UserType, revokedAt: null },
    select: {
      id: true, label: true, permissions: true,
      createdAt: true, expiresAt: true, lastUsedAt: true,
      ipWhitelist: { select: { id: true, ipAddress: true, label: true, isActive: true } },
    },
    orderBy: { createdAt: 'desc' },
  });
}

// ── Revoke API key ─────────────────────────────────────────────────────────────
export async function revokeApiKey(userId: string, keyId: string) {
  const key = await prismaRead.apiKey.findFirst({
    where: { id: keyId, userId, revokedAt: null },
  });
  if (!key) throw new AppError('API_KEY_NOT_FOUND', 404);

  await prismaWrite.apiKey.update({
    where: { id: keyId },
    data: { revokedAt: new Date() },
  });
}

// ── Add IP to whitelist ────────────────────────────────────────────────────────
export async function addIpToWhitelist(
  userId: string,
  keyId: string,
  ipAddress: string,
  label?: string,
) {
  const key = await prismaRead.apiKey.findFirst({ where: { id: keyId, userId, revokedAt: null } });
  if (!key) throw new AppError('API_KEY_NOT_FOUND', 404);

  return prismaWrite.apiKeyIpWhitelist.upsert({
    where: { apiKeyId_ipAddress: { apiKeyId: keyId, ipAddress } },
    create: { apiKeyId: keyId, ipAddress, label: label ?? null, addedBy: userId },
    update: { isActive: true, label: label ?? null },
  });
}

// ── Remove IP from whitelist ──────────────────────────────────────────────────
export async function removeIpFromWhitelist(userId: string, keyId: string, ipId: string) {
  const key = await prismaRead.apiKey.findFirst({ where: { id: keyId, userId, revokedAt: null } });
  if (!key) throw new AppError('API_KEY_NOT_FOUND', 404);

  await prismaWrite.apiKeyIpWhitelist.update({
    where: { id: ipId },
    data: { isActive: false },
  });
}

// ── Verify API key (called by /internal/auth/verify-api-key) ─────────────────
export async function verifyApiKey(rawKey: string, requestIp: string) {
  const keyHash = sha256(rawKey);
  const apiKey = await prismaRead.apiKey.findUnique({
    where: { keyHash },
    include: { ipWhitelist: { where: { isActive: true } } },
  });

  if (!apiKey || apiKey.revokedAt) throw new AppError('INVALID_API_KEY', 401);
  if (apiKey.expiresAt && apiKey.expiresAt < new Date()) throw new AppError('API_KEY_EXPIRED', 401);

  // IP whitelist check (only if any IPs are configured)
  if (apiKey.ipWhitelist.length > 0) {
    const allowed = apiKey.ipWhitelist.some((w) => w.ipAddress === requestIp);
    if (!allowed) throw new AppError('IP_NOT_WHITELISTED', 403);
  }

  // Update lastUsedAt async
  prismaWrite.apiKey.update({
    where: { id: apiKey.id },
    data: { lastUsedAt: new Date() },
  }).catch(() => void 0);

  return { userId: apiKey.userId, userType: apiKey.userType, permissions: apiKey.permissions };
}
