import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { validate } from '../middleware/validate';
import { authenticate, authenticateLoginPending } from '../middleware/authenticate';
import { otpSendRateLimit, totpRateLimit } from '../middleware/rateLimiter';
import { sendOtp, setupTotp, confirmTotp, verifyTotpAtLogin, disableTotp } from '../modules/shared/otp-totp.service';
import { requestPasswordReset, resetPassword, regenerateViewPassword } from '../modules/shared/password.service';
import {
  createHmacApiKey,
  createSelfGeneratedApiKey,
  listApiKeys,
  updateApiKey,
  revokeApiKey,
  addIpToWhitelist,
  removeIpFromWhitelist,
} from '../modules/shared/apikey.service';
import { issueTokensAndCreateSession } from '../modules/live/live.service';
import { verifyOtpCode } from '../utils/otp';
import { verifyTotpCode } from '../utils/totp';
import { hashFingerprint } from '../utils/hash';
import { prismaRead } from '../lib/prisma';
import { AppError } from '../utils/errors';
import { UserType } from '@prisma/client';

const router = Router();

// ─────────────────────────────────────────────────────────────────────────────
// OTP
// ─────────────────────────────────────────────────────────────────────────────

const sendOtpSchema = z.object({
  email:   z.string().email(),
  purpose: z.enum(['email_verify', 'forgot_password', 'withdrawal_confirm', 'twofa_setup']),
});

// POST /api/auth/otp/send
router.post('/otp/send', otpSendRateLimit, validate(sendOtpSchema), async (req: Request, res: Response) => {
  await sendOtp(req.body.email, req.body.purpose);
  res.json({ success: true, message: `OTP sent to ${req.body.email}` });
});

// POST /api/auth/otp/verify — login 2FA gate (requires login_pending token)
router.post('/otp/verify', authenticateLoginPending, async (req: Request, res: Response) => {
  const { otp, deviceFingerprint, deviceLabel } = req.body as {
    otp: string; deviceFingerprint?: string; deviceLabel?: string;
  };
  if (!otp) { res.status(400).json({ success: false, message: 'otp is required' }); return; }

  const result = await verifyOtpCode(req.user!.sub, 'login', otp);
  if (!result.success) throw new AppError(result.reason ?? 'INVALID_OTP', 400);

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

// ─────────────────────────────────────────────────────────────────────────────
// Email Verification
// ─────────────────────────────────────────────────────────────────────────────

const verifyEmailSchema = z.object({
  email: z.string().email(),
  otp:   z.string().length(6),
});

/**
 * POST /api/auth/verify-email
 *
 * Step-2 of the registration flow. The user submits the 6-digit OTP that was
 * emailed on registration (or re-sent via POST /api/auth/otp/send).
 *
 * Flow:
 *   1. Look up the live user by email via user-service internal API.
 *   2. Verify the OTP stored in Redis under `otp:email_verify:<email>`.
 *   3. PATCH user-service to mark emailVerified = true.
 *   4. Return 200 — frontend can now redirect to the login/dashboard page.
 *
 * Idempotent: calling it again after success is safe (OTP is consumed on first
 * verification; subsequent calls will return EXPIRED_OR_NOT_FOUND via a 400).
 */
router.post('/verify-email', validate(verifyEmailSchema), async (req: Request, res: Response) => {
  const { email, otp } = req.body as { email: string; otp: string };

  // 1. Resolve the user — we need their userId to delete the OTP key and call user-service
  const userResp = await fetch(
    `${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/by-email`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-service-secret': process.env.INTERNAL_SERVICE_SECRET!,
      },
      body: JSON.stringify({ email, userType: 'live' }),
    },
  );

  if (!userResp.ok) {
    if (userResp.status === 403) {
      // 403 indicates INTERNAL_SERVICE_SECRET mismatch
      throw new AppError('INTERNAL_SERVICE_UNAUTHORIZED', 500, 'Internal service authentication failed');
    }
    // Return a generic message for 404 — avoid leaking whether the email exists
    throw new AppError('INVALID_EMAIL_OR_OTP', 400);
  }

  const user = await userResp.json() as { userId: string };

  // 2. Verify OTP — keyed by email (matches how createOtp was called in live.service.ts)
  const result = await verifyOtpCode(email, 'email_verify', otp);
  if (!result.success) {
    const codeMap: Record<string, number> = {
      EXPIRED_OR_NOT_FOUND: 400,
      MAX_ATTEMPTS_EXCEEDED: 429,
      INVALID_OTP: 400,
    };
    throw new AppError(result.reason ?? 'INVALID_EMAIL_OR_OTP', codeMap[result.reason ?? ''] ?? 400);
  }

  // 3. Mark email as verified in user-service
  const patchResp = await fetch(
    `${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/${user.userId}/verify-email`,
    {
      method: 'PATCH',
      headers: { 'x-service-secret': process.env.INTERNAL_SERVICE_SECRET! },
    },
  );

  if (!patchResp.ok) {
    throw new AppError('EMAIL_VERIFY_PATCH_FAILED', 502);
  }

  res.json({ success: true, message: 'Email verified successfully. You can now log in.' });
});


// ─────────────────────────────────────────────────────────────────────────────

// POST /api/auth/totp/setup  [auth required]
router.post('/totp/setup', authenticate, totpRateLimit, async (req: Request, res: Response) => {
  const result = await setupTotp(req.user!.sub, req.user!.userType, req.user!.sub);
  res.json({ success: true, data: result });
});

// POST /api/auth/totp/confirm  [auth required]
router.post('/totp/confirm', authenticate, totpRateLimit, async (req: Request, res: Response) => {
  const { code } = req.body as { code: string };
  if (!code) { res.status(400).json({ success: false, message: 'code is required' }); return; }
  const result = await confirmTotp(req.user!.sub, req.user!.userType, code);
  res.json({ success: true, ...result });
});

// POST /api/auth/totp/verify — login 2FA gate (requires login_pending token)
router.post('/totp/verify', authenticateLoginPending, totpRateLimit, async (req: Request, res: Response) => {
  const { code, deviceFingerprint, deviceLabel } = req.body as {
    code: string; deviceFingerprint?: string; deviceLabel?: string;
  };
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

// DELETE /api/auth/totp  [auth required]
router.delete('/totp', authenticate, async (req: Request, res: Response) => {
  const { code } = req.body as { code: string };
  if (!code) { res.status(400).json({ success: false, message: 'code is required to disable 2FA' }); return; }
  const result = await disableTotp(req.user!.sub, req.user!.userType, code);
  res.json({ success: true, ...result });
});

// ─────────────────────────────────────────────────────────────────────────────
// Password
// ─────────────────────────────────────────────────────────────────────────────

const forgotSchema  = z.object({ email: z.string().email(), userType: z.enum(['live', 'demo']) });
const resetSchema   = z.object({ resetToken: z.string().min(1), newPassword: z.string().min(8) });

router.post('/password/forgot', otpSendRateLimit, validate(forgotSchema), async (req: Request, res: Response) => {
  await requestPasswordReset(req.body.email, req.body.userType);
  res.json({ success: true, message: 'If an account exists, a reset code has been sent to your email' });
});

router.post('/password/reset', validate(resetSchema), async (req: Request, res: Response) => {
  const result = await resetPassword(req.body.resetToken, req.body.newPassword);
  res.json({ success: true, ...result });
});

router.post('/regenerate-view-password', authenticate, async (req: Request, res: Response) => {
  const result = await regenerateViewPassword(req.user!.sub, req.user!.userType);
  res.json({ success: true, data: result });
});

// ─────────────────────────────────────────────────────────────────────────────
// API Keys — 2FA-gated mutation guard
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sensitive API key operations (create, edit label/permissions, revoke, IP whitelist mutations)
 * require a fresh OTP or TOTP code to be passed in the request body.
 * This middleware checks `x-api-key-code` header against the user's active 2FA method.
 */
async function requireApiKeyCode(req: Request, res: Response, next: () => void): Promise<void> {
  const code = req.headers['x-api-key-code'] as string | undefined;
  if (!code) {
    res.status(400).json({
      success: false,
      message: 'This operation requires a 2FA code. Pass it in the X-Api-Key-Code header.',
    });
    return;
  }

  const userId   = req.user!.sub;
  const userType = req.user!.userType;

  // Try TOTP first
  const totpRecord = await prismaRead.userTotpSecret.findUnique({
    where: { userId_userType: { userId, userType: userType as UserType } },
  });

  if (totpRecord?.isVerified) {
    const valid = verifyTotpCode(totpRecord.secretEnc, code);
    if (!valid) { res.status(400).json({ success: false, message: 'Invalid authenticator code' }); return; }
  } else {
    // Fall back to email OTP (must have been sent via /api/auth/otp/send with purpose twofa_setup)
    const result = await verifyOtpCode(userId, 'twofa_setup', code);
    if (!result.success) { res.status(400).json({ success: false, message: 'Invalid or expired OTP code' }); return; }
  }

  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// API Keys — Endpoints
// ─────────────────────────────────────────────────────────────────────────────

const createHmacSchema = z.object({
  label:         z.string().min(1).max(100),
  permissions:   z.array(z.string()).optional(),
  expiresInDays: z.coerce.number().int().min(1).max(365).optional(),
});

const createSelfGenSchema = z.object({
  label:         z.string().min(1).max(100),
  keyType:       z.enum(['rsa', 'ed25519']),
  publicKey:     z.string().min(50),   // PEM string
  permissions:   z.array(z.string()).optional(),
  expiresInDays: z.coerce.number().int().min(1).max(365).optional(),
});

const updateKeySchema = z.object({
  label:       z.string().min(1).max(100).optional(),
  permissions: z.array(z.string()).min(1).optional(),
}).refine((d) => d.label !== undefined || d.permissions !== undefined, {
  message: 'At least one of label or permissions is required',
});

const addIpSchema = z.object({
  ipAddress: z.string().ip(),
  label:     z.string().optional(),
});

// GET — list all API keys (no 2FA required)
router.get('/api-keys', authenticate, async (req: Request, res: Response) => {
  const keys = await listApiKeys(req.user!.sub, req.user!.userType);
  res.json({ success: true, data: keys });
});

// POST — create HMAC key  [2FA required via X-Api-Key-Code header]
router.post('/api-keys/hmac', authenticate, validate(createHmacSchema), requireApiKeyCode, async (req: Request, res: Response) => {
  const result = await createHmacApiKey({
    userId:        req.user!.sub,
    userType:      req.user!.userType,
    label:         req.body.label,
    permissions:   req.body.permissions,
    expiresInDays: req.body.expiresInDays,
  });
  res.status(201).json({ success: true, data: result });
});

// POST — create RSA/Ed25519 key  [2FA required]
router.post('/api-keys/self-generated', authenticate, validate(createSelfGenSchema), requireApiKeyCode, async (req: Request, res: Response) => {
  const result = await createSelfGeneratedApiKey({
    userId:        req.user!.sub,
    userType:      req.user!.userType,
    label:         req.body.label,
    keyType:       req.body.keyType,
    publicKey:     req.body.publicKey,
    permissions:   req.body.permissions,
    expiresInDays: req.body.expiresInDays,
  });
  res.status(201).json({ success: true, data: result });
});

// PATCH — edit label / permissions  [2FA required]
router.patch('/api-keys/:id', authenticate, validate(updateKeySchema), requireApiKeyCode, async (req: Request, res: Response) => {
  const result = await updateApiKey(
    req.user!.sub, req.params.id!, req.body.label, req.body.permissions,
  );
  res.json({ success: true, data: result });
});

// DELETE — revoke key  [2FA required]
router.delete('/api-keys/:id', authenticate, requireApiKeyCode, async (req: Request, res: Response) => {
  await revokeApiKey(req.user!.sub, req.params.id!);
  res.json({ success: true, message: 'API key revoked' });
});

// POST — add IP to whitelist  [2FA required]
router.post('/api-keys/:id/ips', authenticate, validate(addIpSchema), requireApiKeyCode, async (req: Request, res: Response) => {
  const result = await addIpToWhitelist(req.user!.sub, req.params.id!, req.body.ipAddress, req.body.label);
  res.status(201).json({ success: true, data: result });
});

// DELETE — remove IP  [2FA required]
router.delete('/api-keys/:id/ips/:ipId', authenticate, requireApiKeyCode, async (req: Request, res: Response) => {
  await removeIpFromWhitelist(req.user!.sub, req.params.id!, req.params.ipId!);
  res.json({ success: true, message: 'IP removed from whitelist' });
});

export default router;
