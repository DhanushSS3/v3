import { Request, Response, NextFunction } from 'express';
import { getRedis } from '../lib/redis';

interface RateLimitOptions {
  windowSeconds: number;
  max: number;
  keyFn: (req: Request) => string;
  message?: string;
}

/**
 * Redis-backed sliding window rate limiter.
 * More accurate than express-rate-limit's in-memory counter
 * because it works across multiple service instances.
 */
export function redisRateLimit(opts: RateLimitOptions) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const redis = getRedis();
    const key = `rl:${opts.keyFn(req)}`;
    const now = Date.now();
    const windowStart = now - opts.windowSeconds * 1000;

    // Sliding window: remove old timestamps, add current, count remaining
    const results = await redis
      .multi()
      .zremrangebyscore(key, '-inf', windowStart)
      .zadd(key, now, `${now}-${Math.random()}`)
      .zcard(key)
      .expire(key, opts.windowSeconds)
      .exec();

    const cardResult = results?.[2] as [Error | null, number] | null;
    const count: number = cardResult?.[1] ?? 0;
    const remaining = opts.max - count;

    res.setHeader('X-RateLimit-Limit', opts.max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, remaining));

    if (remaining < 0) {
      res.status(429).json({
        success: false,
        message: opts.message ?? 'Too many requests. Please try again later.',
        retryAfter: opts.windowSeconds,
      });
      return;
    }

    next();
  };
}

// ── Pre-configured rate limiters ──────────────────────────────────────────────

export const loginRateLimit = redisRateLimit({
  windowSeconds: 15 * 60,
  max: 5,
  keyFn: (req) => `login:${req.ip}:${String(req.body?.email ?? '')}`,
  message: 'Too many login attempts. Please wait 15 minutes.',
});

export const registerRateLimit = redisRateLimit({
  windowSeconds: 60 * 60,
  max: 3,
  keyFn: (req) => `register:${req.ip}`,
  message: 'Too many registration attempts. Please wait 1 hour.',
});

export const otpSendRateLimit = redisRateLimit({
  windowSeconds: 10 * 60,
  max: 3,
  keyFn: (req) => `otp_send:${String(req.body?.email ?? req.body?.phone ?? req.ip)}`,
  message: 'Too many OTP requests. Please wait 10 minutes.',
});

export const totpRateLimit = redisRateLimit({
  windowSeconds: 5 * 60,
  max: 5,
  keyFn: (req) => `totp:${req.ip}`,
});
