import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { validate } from '../middleware/validate';
import { loginRateLimit } from '../middleware/rateLimiter';
import { authenticate } from '../middleware/authenticate';
import { refreshSession, logoutSession } from '../modules/shared/session.service';
import { adminLoginStep1, adminLoginStep2 } from '../modules/admin/admin.service';

const router = Router();

const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });
const otpSchema   = z.object({ adminId: z.string().uuid(), email: z.string().email(), otp: z.string().length(6) });
const refreshSchema = z.object({ refreshToken: z.string().min(1) });

// POST /api/admin/auth/login — Step 1: password → send OTP
router.post('/login', loginRateLimit, validate(loginSchema), async (req: Request, res: Response) => {
  const result = await adminLoginStep1(req.body.email, req.body.password);
  res.json({ success: true, data: result });
});

// POST /api/admin/auth/verify-otp — Step 2: OTP → issue tokens
router.post('/verify-otp', loginRateLimit, validate(otpSchema), async (req: Request, res: Response) => {
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  const ua = req.headers['user-agent'] ?? '';
  const result = await adminLoginStep2(req.body.adminId, req.body.email, req.body.otp, ip, ua);
  res.json({ success: true, data: result });
});

// POST /api/admin/auth/refresh-token
router.post('/refresh-token', validate(refreshSchema), async (req: Request, res: Response) => {
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  const ua = req.headers['user-agent'] ?? '';
  const data = await refreshSession(req.body.refreshToken, ip, ua);
  res.json({ success: true, data });
});

// POST /api/admin/auth/logout
router.post('/logout', authenticate, async (req: Request, res: Response) => {
  await logoutSession(req.user!.sid);
  res.json({ success: true, message: 'Logged out successfully' });
});

export default router;
