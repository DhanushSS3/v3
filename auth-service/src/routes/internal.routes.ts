import { Router, Request, Response } from 'express';
import { authenticateInternal } from '../middleware/authenticate';
import { verifyToken } from '../utils/jwt';
import { sha256 } from '../utils/hash';
import { prismaRead } from '../lib/prisma';
import { verifyApiKey, verifySelfGeneratedApiKey } from '../modules/shared/apikey.service';

const router = Router();

// All internal routes require the service secret header
router.use(authenticateInternal);

/**
 * POST /internal/auth/verify
 * Called by other services to validate a JWT.
 */
router.post('/verify', async (req: Request, res: Response) => {
  const { token, checkSession } = req.body as { token: string; checkSession?: boolean };
  if (!token) { res.status(400).json({ success: false, message: 'token is required' }); return; }

  let payload;
  try {
    payload = verifyToken(token);
  } catch {
    res.status(401).json({ success: false, message: 'Invalid or expired token' });
    return;
  }

  if (payload.typ !== 'access') {
    res.status(401).json({ success: false, message: 'Invalid token type' });
    return;
  }

  if (checkSession) {
    const tokenHash = sha256(payload.jti);
    const session   = await prismaRead.session.findUnique({ where: { tokenHash } });
    if (!session || session.revokedAt || session.expiresAt < new Date()) {
      res.status(401).json({ success: false, message: 'Session expired or revoked' });
      return;
    }
  }

  res.json({
    success: true,
    data: {
      userId:        payload.sub,
      sessionId:     payload.sid,
      userType:      payload.userType,
      accountNumber: payload.accountNumber,
      groupName:     payload.groupName,
      currency:      payload.currency,
      permissions:   payload.permissions ?? [],
    },
  });
});

/**
 * POST /internal/auth/verify-api-key
 * HMAC keys only — raw key in body.
 */
router.post('/verify-api-key', async (req: Request, res: Response) => {
  const { apiKey } = req.body as { apiKey: string };
  const requestIp  = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  if (!apiKey) { res.status(400).json({ success: false, message: 'apiKey is required' }); return; }
  const result = await verifyApiKey(apiKey, requestIp);
  res.json({ success: true, data: result });
});

/**
 * POST /internal/auth/verify-signed-api-key
 * RSA / Ed25519 self-generated keys.
 * Body: { keyId, payload, signature }
 */
router.post('/verify-signed-api-key', async (req: Request, res: Response) => {
  const { keyId, payload, signature } = req.body as { keyId: string; payload: string; signature: string };
  const requestIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  if (!keyId || !payload || !signature) {
    res.status(400).json({ success: false, message: 'keyId, payload, and signature are required' });
    return;
  }
  const result = await verifySelfGeneratedApiKey(keyId, payload, signature, requestIp);
  res.json({ success: true, data: result });
});

export default router;
