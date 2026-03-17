import { prismaWrite, prismaRead } from '../../lib/prisma';
import { sha256 } from '../../utils/hash';
import { AppError } from '../../utils/errors';
import { randomBytes, createVerify } from 'crypto';
import { UserType, ApiKeyType } from '@prisma/client';

// ── Constants ─────────────────────────────────────────────────────────────────
const DEFAULT_PERMISSIONS = ['READ'];
const DEFAULT_EXPIRY_DAYS = 365;
const MAX_KEYS_PER_USER   = 10;

// ── Types ─────────────────────────────────────────────────────────────────────
interface CreateHmacKeyInput {
  userId:        string;
  userType:      string;
  label:         string;
  permissions?:  string[];
  expiresInDays?: number;
}

interface CreateSelfGeneratedKeyInput {
  userId:        string;
  userType:      string;
  label:         string;
  keyType:       'rsa' | 'ed25519';
  publicKey:     string; // PEM-encoded
  permissions?:  string[];
  expiresInDays?: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
async function assertKeyLimit(userId: string, userType: string): Promise<void> {
  const count = await prismaRead.apiKey.count({
    where: { userId, userType: userType as UserType, revokedAt: null },
  });
  if (count >= MAX_KEYS_PER_USER) throw new AppError('API_KEY_LIMIT_REACHED', 400);
}

// ── Create — HMAC (system-generated) ─────────────────────────────────────────
export async function createHmacApiKey(input: CreateHmacKeyInput) {
  await assertKeyLimit(input.userId, input.userType);

  const rawKey    = `lfx_${randomBytes(32).toString('hex')}`;
  const keyHash   = sha256(rawKey);
  const expiresAt = new Date(Date.now() + ((input.expiresInDays ?? DEFAULT_EXPIRY_DAYS) * 86_400_000));

  const key = await prismaWrite.apiKey.create({
    data: {
      userId:      input.userId,
      userType:    input.userType as UserType,
      keyType:     'hmac',
      keyHash,
      label:       input.label,
      permissions: input.permissions ?? DEFAULT_PERMISSIONS,
      expiresAt,
    },
    select: { id: true, label: true, keyType: true, permissions: true, createdAt: true, expiresAt: true },
  });

  return { ...key, key: rawKey, warning: 'Store this key securely — it will never be shown again.' };
}

// ── Create — Self-generated (RSA / Ed25519) ───────────────────────────────────
export async function createSelfGeneratedApiKey(input: CreateSelfGeneratedKeyInput) {
  await assertKeyLimit(input.userId, input.userType);

  // Basic PEM validation: must start with -----BEGIN ... PUBLIC KEY-----
  if (!input.publicKey.trim().startsWith('-----BEGIN')) {
    throw new AppError('INVALID_PUBLIC_KEY_FORMAT', 400);
  }

  const expiresAt = new Date(Date.now() + ((input.expiresInDays ?? DEFAULT_EXPIRY_DAYS) * 86_400_000));

  const key = await prismaWrite.apiKey.create({
    data: {
      userId:      input.userId,
      userType:    input.userType as UserType,
      keyType:     input.keyType as ApiKeyType,
      publicKey:   input.publicKey,
      label:       input.label,
      permissions: input.permissions ?? DEFAULT_PERMISSIONS,
      expiresAt,
    },
    select: { id: true, label: true, keyType: true, permissions: true, createdAt: true, expiresAt: true },
  });

  return { ...key, message: 'Sign your requests using your private key. Public key registered.' };
}

// ── List ──────────────────────────────────────────────────────────────────────
export async function listApiKeys(userId: string, userType: string) {
  return prismaRead.apiKey.findMany({
    where: { userId, userType: userType as UserType, revokedAt: null },
    select: {
      id: true, label: true, keyType: true, permissions: true,
      createdAt: true, expiresAt: true, lastUsedAt: true,
      ipWhitelist: { select: { id: true, ipAddress: true, label: true, isActive: true } },
    },
    orderBy: { createdAt: 'desc' },
  });
}

// ── Edit (label + permissions) ─────────────────────────────────────────────────
export async function updateApiKey(
  userId:      string,
  keyId:       string,
  label?:      string,
  permissions?: string[],
) {
  const key = await prismaRead.apiKey.findFirst({
    where: { id: keyId, userId, revokedAt: null },
  });
  if (!key) throw new AppError('API_KEY_NOT_FOUND', 404);

  return prismaWrite.apiKey.update({
    where: { id: keyId },
    data: {
      ...(label       !== undefined && { label }),
      ...(permissions !== undefined && { permissions }),
    },
    select: { id: true, label: true, permissions: true, updatedAt: true },
  });
}

// ── Revoke ────────────────────────────────────────────────────────────────────
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

// ── IP Whitelist ──────────────────────────────────────────────────────────────
export async function addIpToWhitelist(
  userId: string, keyId: string, ipAddress: string, label?: string,
) {
  const key = await prismaRead.apiKey.findFirst({ where: { id: keyId, userId, revokedAt: null } });
  if (!key) throw new AppError('API_KEY_NOT_FOUND', 404);

  return prismaWrite.apiKeyIpWhitelist.upsert({
    where: { apiKeyId_ipAddress: { apiKeyId: keyId, ipAddress } },
    create: { apiKeyId: keyId, ipAddress, label: label ?? null, addedBy: userId },
    update: { isActive: true, label: label ?? null },
  });
}

export async function removeIpFromWhitelist(userId: string, keyId: string, ipId: string) {
  const key = await prismaRead.apiKey.findFirst({ where: { id: keyId, userId, revokedAt: null } });
  if (!key) throw new AppError('API_KEY_NOT_FOUND', 404);

  await prismaWrite.apiKeyIpWhitelist.update({
    where: { id: ipId },
    data: { isActive: false },
  });
}

// ── Verify (called by /internal/auth/verify-api-key — HMAC path only) ────────
export async function verifyApiKey(rawKey: string, requestIp: string) {
  const keyHash = sha256(rawKey);
  const apiKey = await prismaRead.apiKey.findUnique({
    where: { keyHash },
    include: { ipWhitelist: { where: { isActive: true } } },
  });

  if (!apiKey || apiKey.revokedAt) throw new AppError('INVALID_API_KEY', 401);
  if (apiKey.expiresAt && apiKey.expiresAt < new Date()) throw new AppError('API_KEY_EXPIRED', 401);

  if (apiKey.ipWhitelist.length > 0) {
    const allowed = apiKey.ipWhitelist.some((w) => w.ipAddress === requestIp);
    if (!allowed) throw new AppError('IP_NOT_WHITELISTED', 403);
  }

  // Update lastUsedAt non-blocking
  prismaWrite.apiKey.update({ where: { id: apiKey.id }, data: { lastUsedAt: new Date() } })
    .catch(() => void 0);

  return { userId: apiKey.userId, userType: apiKey.userType, permissions: apiKey.permissions, keyType: apiKey.keyType };
}

/**
 * Verify a self-generated (RSA/Ed25519) API key request.
 * The client signs a canonical request string with their private key.
 * We verify using the stored public key.
 *
 * @param keyId        - The API key ID (sent in header X-API-Key-Id)
 * @param payload      - The canonical request string that was signed (e.g. timestamp + method + path)
 * @param signature    - Base64-encoded signature from the client
 * @param requestIp    - Caller IP for whitelist check
 */
export async function verifySelfGeneratedApiKey(
  keyId:     string,
  payload:   string,
  signature: string,
  requestIp: string,
) {
  const apiKey = await prismaRead.apiKey.findFirst({
    where: { id: keyId, revokedAt: null },
    include: { ipWhitelist: { where: { isActive: true } } },
  });

  if (!apiKey || !apiKey.publicKey) throw new AppError('INVALID_API_KEY', 401);
  if (apiKey.keyType === 'hmac') throw new AppError('WRONG_AUTH_METHOD', 400);
  if (apiKey.expiresAt && apiKey.expiresAt < new Date()) throw new AppError('API_KEY_EXPIRED', 401);

  if (apiKey.ipWhitelist.length > 0) {
    if (!apiKey.ipWhitelist.some((w) => w.ipAddress === requestIp)) {
      throw new AppError('IP_NOT_WHITELISTED', 403);
    }
  }

  const algorithm = apiKey.keyType === 'rsa' ? 'RSA-SHA256' : 'ED25519';
  const verify = createVerify(algorithm);
  verify.update(payload);
  const valid = verify.verify(apiKey.publicKey, signature, 'base64');
  if (!valid) throw new AppError('INVALID_SIGNATURE', 401);

  prismaWrite.apiKey.update({ where: { id: apiKey.id }, data: { lastUsedAt: new Date() } })
    .catch(() => void 0);

  return { userId: apiKey.userId, userType: apiKey.userType, permissions: apiKey.permissions, keyType: apiKey.keyType };
}
