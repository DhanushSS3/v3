import { getRedis } from '../lib/redis';

// Redis key for atomic counter per year
const counterKey = (year: number) => `account_number_seq:${year}`;

/**
 * Generate a unique account number: LU-YYYY-000001
 * Uses Redis INCR for atomic sequential numbering per year.
 */
export async function generateAccountNumber(prefix: 'LU' | 'DU' | 'SP' | 'MAM'): Promise<string> {
  const redis = getRedis();
  const year = new Date().getFullYear();
  const key = `${prefix}_${counterKey(year)}`;

  const seq = await redis.incr(key);
  // Set expiry to slightly past end of year (auto-cleanup, won't reset mid-year)
  if (seq === 1) {
    await redis.expireat(key, Math.floor(new Date(`${year + 1}-01-15`).getTime() / 1000));
  }

  // Zero-pad to 6 digits: LU-2025-000001
  return `${prefix}-${year}-${String(seq).padStart(6, '0')}`;
}
