import { Router, Request, Response } from 'express';
import { registerController, loginController } from '../modules/demo/demo.controller';
import { validate } from '../middleware/validate';
import { loginRateLimit, registerRateLimit } from '../middleware/rateLimiter';
import { authenticate } from '../middleware/authenticate';
import { demoRegisterSchema, demoLoginSchema } from '../modules/demo/demo.schema';
import { refreshSession, logoutSession } from '../modules/shared/session.service';

const router = Router();

router.post('/register', registerRateLimit, validate(demoRegisterSchema), registerController);
router.post('/login', loginRateLimit, validate(demoLoginSchema), loginController);

router.post('/refresh-token', async (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  if (!refreshToken) { res.status(400).json({ success: false, message: 'refreshToken is required' }); return; }
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  const ua = req.headers['user-agent'] ?? '';
  const data = await refreshSession(refreshToken, ip, ua);
  res.json({ success: true, data });
});

router.post('/logout', authenticate, async (req: Request, res: Response) => {
  await logoutSession(req.user!.sid);
  res.json({ success: true, message: 'Logged out successfully' });
});

export default router;
