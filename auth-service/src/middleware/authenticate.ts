import { Request, Response, NextFunction } from 'express';
import { verifyToken, JwtPayload } from '../utils/jwt';
import { sha256 } from '../utils/hash';
import { prismaRead } from '../lib/prisma';

// Extend Express Request with user context
declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload;
    }
  }
}

/**
 * JWT authentication middleware.
 * 1. Extracts Bearer token from Authorization header
 * 2. Verifies signature + expiry
 * 3. Checks typ = 'access' (rejects refresh / login_pending tokens)
 * 4. Validates session still exists in DB (not revoked)
 */
export async function authenticate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ success: false, message: 'Missing or malformed Authorization header' });
    return;
  }

  const token = authHeader.slice(7);

  let payload: JwtPayload;
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

  // Check session is not revoked in DB
  const tokenHash = sha256(payload.jti);
  const session = await prismaRead.session.findUnique({ where: { tokenHash } });
  if (!session || session.revokedAt !== null || session.expiresAt < new Date()) {
    res.status(401).json({ success: false, message: 'Session expired or revoked' });
    return;
  }

  req.user = payload;
  next();
}

/**
 * Same as authenticate but requires typ = 'login_pending'
 * Used for the 2FA gate — TOTP and OTP verify endpoints.
 */
export async function authenticateLoginPending(
  req: Request, res: Response, next: NextFunction,
): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ success: false, message: 'Missing login token' });
    return;
  }

  const token = authHeader.slice(7);
  let payload: JwtPayload;
  try {
    payload = verifyToken(token);
  } catch {
    res.status(401).json({ success: false, message: 'Invalid or expired login token' });
    return;
  }

  if (payload.typ !== 'login_pending') {
    res.status(401).json({ success: false, message: 'Invalid token type for this operation' });
    return;
  }

  req.user = payload;
  next();
}

/**
 * Internal service auth — validates X-Service-Secret header.
 * Used by other microservices calling /internal/* endpoints.
 */
export function authenticateInternal(req: Request, res: Response, next: NextFunction): void {
  const secret = req.headers['x-service-secret'];
  if (!secret || secret !== process.env.INTERNAL_SERVICE_SECRET) {
    res.status(403).json({ success: false, message: 'Forbidden' });
    return;
  }
  next();
}

/** Require a specific userType on the JWT */
export function requireUserType(...types: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user || !types.includes(req.user.userType)) {
      res.status(403).json({
        success: false,
        message: `Access restricted to: ${types.join(', ')}`,
      });
      return;
    }
    next();
  };
}
