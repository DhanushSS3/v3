import { Router, Request, Response } from 'express';
import { config } from '../config/env';
import {
  getLiveUserByEmail,
  getLiveUsersByEmail,
  getDemoUserByEmail,
  getUserById,
  isPhoneAvailable,
  updateUserPassword,
  updateViewPassword,
  markEmailVerified,
  touchLastLogin,
} from '../modules/user/user.service';

const router = Router();

// ── Internal auth middleware — x-service-secret ───────────────────────────────
router.use((req: Request, res: Response, next: () => void) => {
  if (req.headers['x-service-secret'] !== config.internalSecret) {
    res.status(403).json({ success: false, message: 'Forbidden' });
    return;
  }
  next();
});

// ─────────────────────────────────────────────────────────────────────────────
// Auth-service calls these endpoints during login/register
// ─────────────────────────────────────────────────────────────────────────────

/**
 * POST /internal/users/by-email
 * Returns auth context for login verification.
 * If user has multiple accounts for the email, returns the most recently created active one.
 * auth-service can use /internal/users/by-email/all to let user pick account.
 */
router.post('/users/by-email', async (req: Request, res: Response) => {
  const { email, userType } = req.body as { email: string; userType?: string };
  if (!email) { res.status(400).json({ success: false, message: 'email is required' }); return; }

  const user = userType === 'demo'
    ? await getDemoUserByEmail(email)
    : await getLiveUserByEmail(email);

  if (!user) { res.status(404).json({ success: false, message: 'User not found' }); return; }
  res.json(user);
});

/**
 * POST /internal/users/by-email/all
 * Returns ALL accounts for an email (for multi-account login selector).
 */
router.post('/users/by-email/all', async (req: Request, res: Response) => {
  const { email } = req.body as { email: string };
  if (!email) { res.status(400).json({ success: false, message: 'email is required' }); return; }
  const users = await getLiveUsersByEmail(email);
  res.json({ success: true, data: users });
});

/**
 * GET /internal/users/:id
 * Fetch user auth context by ID (used by auth-service after 2FA verify to issue tokens).
 */
router.get('/users/:id', async (req: Request, res: Response) => {
  const { userType } = req.query as { userType?: string };
  const user = await getUserById(req.params.id!, userType ?? 'live');
  if (!user) { res.status(404).json({ success: false, message: 'User not found' }); return; }
  res.json(user);
});

/**
 * GET /internal/users/check-phone/:phone
 * Pre-flight phone availability check before registration.
 * auth-service can use this to reject early before publishing to Kafka.
 */
router.get('/users/check-phone/:phone', async (req: Request, res: Response) => {
  const available = await isPhoneAvailable(decodeURIComponent(req.params.phone!));
  res.json({ success: true, available });
});

/**
 * PATCH /internal/users/:id/password
 * Called by auth-service after password reset flow.
 */
router.patch('/users/:id/password', async (req: Request, res: Response) => {
  const { passwordHash, userType } = req.body as { passwordHash: string; userType: string };
  if (!passwordHash) { res.status(400).json({ success: false, message: 'passwordHash is required' }); return; }
  await updateUserPassword(req.params.id!, userType ?? 'live', passwordHash);
  res.json({ success: true });
});

/**
 * PATCH /internal/users/:id/view-password
 * Called by auth-service when user regenerates view-only password.
 */
router.patch('/users/:id/view-password', async (req: Request, res: Response) => {
  const { viewPassword } = req.body as { viewPassword: string };
  if (!viewPassword) { res.status(400).json({ success: false, message: 'viewPassword is required' }); return; }
  await updateViewPassword(req.params.id!, viewPassword);
  res.json({ success: true });
});

/**
 * PATCH /internal/users/:id/verify-email
 * Called after OTP verification.
 */
router.patch('/users/:id/verify-email', async (req: Request, res: Response) => {
  await markEmailVerified(req.params.id!);
  res.json({ success: true });
});

/**
 * PATCH /internal/users/:id/touch-login
 * Called after successful login to update lastLoginAt.
 */
router.patch('/users/:id/touch-login', async (req: Request, res: Response) => {
  const { userType } = req.body as { userType?: string };
  await touchLastLogin(req.params.id!, userType ?? 'live');
  res.json({ success: true });
});

export default router;
