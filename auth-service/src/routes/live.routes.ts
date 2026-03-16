import { Router } from 'express';
import { registerController, loginController } from '../modules/live/live.controller';
import { validate } from '../middleware/validate';
import { loginRateLimit, registerRateLimit } from '../middleware/rateLimiter';
import { authenticate } from '../middleware/authenticate';
import { liveRegisterSchema, liveLoginSchema } from '../modules/live/live.schema';
import { refreshSession, logoutSession, listSessions } from '../modules/shared/session.service';
import { regenerateViewPassword } from '../modules/shared/password.service';
import { Request, Response } from 'express';

const router = Router();

// POST /api/live/register
router.post('/register', registerRateLimit, validate(liveRegisterSchema), registerController);

// POST /api/live/login
router.post('/login', loginRateLimit, validate(liveLoginSchema), loginController);

// POST /api/live/refresh-token
router.post('/refresh-token', async (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  if (!refreshToken) { res.status(400).json({ success: false, message: 'refreshToken is required' }); return; }
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  const ua = req.headers['user-agent'] ?? '';
  const data = await refreshSession(refreshToken, ip, ua);
  res.json({ success: true, data });
});

// POST /api/live/logout  [auth required]
router.post('/logout', authenticate, async (req: Request, res: Response) => {
  await logoutSession(req.user!.sid);
  res.json({ success: true, message: 'Logged out successfully' });
});

// GET /api/live/sessions  [auth required]
router.get('/sessions', authenticate, async (req: Request, res: Response) => {
  const sessions = await listSessions(req.user!.sub, req.user!.userType);
  res.json({ success: true, data: sessions });
});

// DELETE /api/live/sessions/:id  [auth required]
router.delete('/sessions/:id', authenticate, async (req: Request, res: Response) => {
  await logoutSession(req.params.id!);
  res.json({ success: true, message: 'Session revoked' });
});

// POST /api/live/regenerate-view-password  [auth required]
router.post('/regenerate-view-password', authenticate, async (req: Request, res: Response) => {
  const result = await regenerateViewPassword(req.user!.sub, req.user!.userType);
  res.json({ success: true, data: result });
});

export default router;
