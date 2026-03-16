import bcrypt from 'bcryptjs';
import { createHash, createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const BCRYPT_ROUNDS = 12;

// ── bcrypt ────────────────────────────────────────────────────────────────────
export const hashPassword = (plain: string): Promise<string> =>
  bcrypt.hash(plain, BCRYPT_ROUNDS);

export const verifyPassword = (plain: string, hash: string): Promise<boolean> =>
  bcrypt.compare(plain, hash);

export const hashOtp = (otp: string): Promise<string> =>
  bcrypt.hash(otp, 10); // Lower rounds — OTPs verify quickly

export const verifyOtp = (otp: string, hash: string): Promise<boolean> =>
  bcrypt.compare(otp, hash);

// ── SHA-256 ───────────────────────────────────────────────────────────────────
export const sha256 = (input: string): string =>
  createHash('sha256').update(input).digest('hex');

// ── AES-256-GCM (for TOTP secrets) ───────────────────────────────────────────
// KEY must be 32 bytes hex string from env (TOTP_ENCRYPTION_KEY)
function getKey(hexKey: string): Buffer {
  const buf = Buffer.from(hexKey, 'hex');
  if (buf.length !== 32) throw new Error('TOTP_ENCRYPTION_KEY must be a 64-char hex string (32 bytes)');
  return buf;
}

export function encryptAES(plaintext: string, hexKey: string): string {
  const key = getKey(hexKey);
  const iv = randomBytes(12); // 96-bit IV for GCM
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Format: iv(24 hex) + authTag(32 hex) + ciphertext(hex)
  return iv.toString('hex') + authTag.toString('hex') + encrypted.toString('hex');
}

export function decryptAES(encoded: string, hexKey: string): string {
  const key = getKey(hexKey);
  const iv = Buffer.from(encoded.slice(0, 24), 'hex');
  const authTag = Buffer.from(encoded.slice(24, 56), 'hex');
  const ciphertext = Buffer.from(encoded.slice(56), 'hex');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return decipher.update(ciphertext).toString('utf8') + decipher.final('utf8');
}

// ── Device fingerprint hash ───────────────────────────────────────────────────
export const hashFingerprint = (raw: string): string => sha256(raw);
