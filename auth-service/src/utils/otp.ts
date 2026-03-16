import { getRedis } from '../lib/redis';
import { hashOtp, verifyOtp } from './hash';
import { config } from '../config/env';

// ── OTP Redis key helpers ─────────────────────────────────────────────────────
const otpKey = (identifier: string, purpose: string) =>
  `otp:${purpose}:${identifier}`;
const lockKey = (identifier: string, purpose: string) =>
  `otp_lock:${purpose}:${identifier}`;

// ── Generate + store ──────────────────────────────────────────────────────────
export function generateOtpCode(): string {
  return String(Math.floor(100000 + Math.random() * 900000));
}

export async function createOtp(identifier: string, purpose: string): Promise<string> {
  const redis = getRedis();
  const lockKey_ = lockKey(identifier, purpose);

  // Check if too many OTPs have been sent
  const lockCount = await redis.get(lockKey_);
  if (lockCount && parseInt(lockCount) >= 3) {
    throw new Error('TOO_MANY_OTP_REQUESTS');
  }

  const code = generateOtpCode();
  const hash = await hashOtp(code);
  const expirySeconds = config.otpExpiresInMinutes * 60;

  const key = otpKey(identifier, purpose);
  await redis.setex(key, expirySeconds, JSON.stringify({ hash, attempts: 0 }));

  // Rate-limit: max 3 OTP sends per 10 min
  await redis.multi()
    .incr(lockKey_)
    .expire(lockKey_, 10 * 60)
    .exec();

  return code;
}

export async function verifyOtpCode(
  identifier: string,
  purpose: string,
  code: string,
): Promise<{ success: boolean; reason?: string }> {
  const redis = getRedis();
  const key = otpKey(identifier, purpose);

  const raw = await redis.get(key);
  if (!raw) return { success: false, reason: 'EXPIRED_OR_NOT_FOUND' };

  const data = JSON.parse(raw) as { hash: string; attempts: number };

  if (data.attempts >= config.otpMaxAttempts) {
    await redis.del(key);
    return { success: false, reason: 'MAX_ATTEMPTS_EXCEEDED' };
  }

  const match = await verifyOtp(code, data.hash);
  if (!match) {
    data.attempts += 1;
    const ttl = await redis.ttl(key);
    await redis.setex(key, Math.max(ttl, 1), JSON.stringify(data));
    return { success: false, reason: 'INVALID_OTP' };
  }

  await redis.del(key); // Consume OTP
  return { success: true };
}
