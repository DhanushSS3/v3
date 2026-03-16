import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { validate } from '../middleware/validate';
import { authenticate, authenticateLoginPending } from '../middleware/authenticate';
import { otpSendRateLimit, totpRateLimit } from '../middleware/rateLimiter';
import { sendOtp, setupTotp, confirmTotp, verifyTotpAtLogin, disableTotp } from '../modules/shared/otp-totp.service';
import { requestPasswordReset, resetPassword, regenerateViewPassword } from '../modules/shared/password.service';
import { createApiKey, listApiKeys, revokeApiKey, addIpToWhitelist, removeIpFromWhitelist } from '../modules/shared/apikey.service';
import { issueTokensAndCreateSession } from '../modules/live/live.service';
import { verifyOtpCode } from '../utils/otp';
import { hashFingerprint } from '../utils/hash';
import { AppError } from '../utils/errors';

const router = Router();

// ── OTP ───────────────────────────────────────────────────────────────────────

const sendOtpSchema = z.object({
  email:   z.string().email(),
  purpose: z.enum(['email_verify', 'forgot_password', 'withdrawal_confirm', 'twofa_setup']),
});

// POST /api/auth/otp/send
router.post('/otp/send', otpSendRateLimit, validate(sendOtpSchema), async (req: Request, res: Response) => {
  await sendOtp(req.body.email, req.body.purpose);
  // Also trigger password reset flow if purpose is forgot_password
  if (req.body.purpose === 'forgot_password') {
    // requestPasswordReset just sends OTP, which sendOtp already handles above
    // reserving for future per-purpose logic
  }
  res.json({ success: true, message: `OTP sent to ${req.body.email}` });
});

// POST /api/auth/otp/verify — for login 2FA gate (requires login_pending token)
router.post('/otp/verify', authenticateLoginPending, async (req: Request, res: Response) => {
  const { otp, deviceFingerprint, deviceLabel } = req.body;
  if (!otp) { res.status(400).json({ success: false, message: 'otp is required' }); return; }

  const result = await verifyOtpCode(req.user!.sub, 'login', otp);
  if (!result.success) throw new AppError(result.reason ?? 'INVALID_OTP', 400);

  // Resolve user context from user-service to issue real tokens
  const userResp = await fetch(`${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/${req.user!.sub}`, {
    headers: { 'x-service-secret': process.env.INTERNAL_SERVICE_SECRET! },
  });
  const ctx = await userResp.json() as {
    userId: string; userType: 'live'; accountNumber: string;
    groupName: string; currency: string; passwordHash: string; isActive: boolean;
  };

  const fp = deviceFingerprint ? hashFingerprint(deviceFingerprint) : null;
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  const ua = req.headers['user-agent'] ?? '';

  const tokens = await issueTokensAndCreateSession(ctx, fp, deviceLabel ?? null, ip, ua, !!fp);
  res.json({ success: true, data: tokens });
});

// ── TOTP ──────────────────────────────────────────────────────────────────────

// POST /api/auth/totp/setup  [auth required]
router.post('/totp/setup', authenticate, totpRateLimit, async (req: Request, res: Response) => {
  const result = await setupTotp(req.user!.sub, req.user!.userType, req.user!.sub);
  res.json({ success: true, data: result });
});

// POST /api/auth/totp/confirm  [auth required]
router.post('/totp/confirm', authenticate, totpRateLimit, async (req: Request, res: Response) => {
  const { code } = req.body;
  if (!code) { res.status(400).json({ success: false, message: 'code is required' }); return; }
  const result = await confirmTotp(req.user!.sub, req.user!.userType, code);
  res.json({ success: true, ...result });
});

// POST /api/auth/totp/verify — for login 2FA gate (requires login_pending token)
router.post('/totp/verify', authenticateLoginPending, totpRateLimit, async (req: Request, res: Response) => {
  const { code, deviceFingerprint, deviceLabel } = req.body;
  if (!code) { res.status(400).json({ success: false, message: 'code is required' }); return; }

  await verifyTotpAtLogin(req.user!.sub, req.user!.userType, code);

  const userResp = await fetch(`${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/${req.user!.sub}`, {
    headers: { 'x-service-secret': process.env.INTERNAL_SERVICE_SECRET! },
  });
  const ctx = await userResp.json() as {
    userId: string; userType: 'live'; accountNumber: string;
    groupName: string; currency: string; passwordHash: string; isActive: boolean;
  };

  const fp = deviceFingerprint ? hashFingerprint(deviceFingerprint) : null;
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  const ua = req.headers['user-agent'] ?? '';

  const tokens = await issueTokensAndCreateSession(ctx, fp, deviceLabel ?? null, ip, ua, false);
  res.json({ success: true, data: tokens });
});

// DELETE /api/auth/totp  [auth required, requires current TOTP code]
router.delete('/totp', authenticate, async (req: Request, res: Response) => {
  const { code } = req.body as { code: string };
  if (!code) { res.status(400).json({ success: false, message: 'code is required to disable 2FA' }); return; }
  const result = await disableTotp(req.user!.sub, req.user!.userType, code);
  res.json({ success: true, ...result });
});

// ── Password ──────────────────────────────────────────────────────────────────

const forgotSchema = z.object({ email: z.string().email(), userType: z.enum(['live', 'demo']) });
const resetSchema = z.object({ resetToken: z.string().min(1), newPassword: z.string().min(8) });

// POST /api/auth/password/forgot
router.post('/password/forgot', otpSendRateLimit, validate(forgotSchema), async (req: Request, res: Response) => {
  await requestPasswordReset(req.body.email, req.body.userType);
  res.json({ success: true, message: 'If an account exists, a reset code has been sent to your email' });
});

// POST /api/auth/password/reset
router.post('/password/reset', validate(resetSchema), async (req: Request, res: Response) => {
  const result = await resetPassword(req.body.resetToken, req.body.newPassword);
  res.json({ success: true, ...result });
});

// POST /api/auth/regenerate-view-password  [auth required]
router.post('/regenerate-view-password', authenticate, async (req: Request, res: Response) => {
  const result = await regenerateViewPassword(req.user!.sub, req.user!.userType);
  res.json({ success: true, data: result });
});

// ── API Keys ──────────────────────────────────────────────────────────────────

const createKeySchema = z.object({
  label:       z.string().min(1).max(100),
  permissions: z.array(z.string()).min(1),
  expiresInDays: z.coerce.number().int().min(1).max(365).optional(),
});

const addIpSchema = z.object({
  ipAddress: z.string().ip(),
  label:     z.string().optional(),
});

router.post(  '/api-keys',            authenticate, validate(createKeySchema), async (req: Request, res: Response) => {
  const result = await createApiKey(req.user!.sub, req.user!.userType, req.body.label, req.body.permissions, req.body.expiresInDays);
  res.status(201).json({ success: true, data: result });
});

router.get(   '/api-keys',            authenticate, async (req: Request, res: Response) => {
  const keys = await listApiKeys(req.user!.sub, req.user!.userType);
  res.json({ success: true, data: keys });
});

router.delete('/api-keys/:id',        authenticate, async (req: Request, res: Response) => {
  await revokeApiKey(req.user!.sub, req.params.id!);
  res.json({ success: true, message: 'API key revoked' });
});

router.post(  '/api-keys/:id/ips',    authenticate, validate(addIpSchema), async (req: Request, res: Response) => {
  const result = await addIpToWhitelist(req.user!.sub, req.params.id!, req.body.ipAddress, req.body.label);
  res.status(201).json({ success: true, data: result });
});

router.delete('/api-keys/:id/ips/:ipId', authenticate, async (req: Request, res: Response) => {
  await removeIpFromWhitelist(req.user!.sub, req.params.id!, req.params.ipId!);
  res.json({ success: true, message: 'IP removed from whitelist' });
});

export default router;
