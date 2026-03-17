import { Router } from 'express';
import { AdminController } from '../modules/admin/admin.controller';
import { requireInternalSecret } from '../middleware';
import { config } from '../config/env';

/**
 * Internal routes — called ONLY by auth-service.
 * Protected by x-service-secret header (requireInternalSecret middleware).
 * Never exposed publicly.
 */
export function createInternalRouter(controller: AdminController): Router {
  const router = Router();

  router.use(requireInternalSecret(config.internalSecret));

  // POST /internal/admins/by-email — auth-service login step 1
  router.post('/admins/by-email', controller.getAuthContext);

  // GET /internal/admins/:id/permissions — auth-service login step 2
  router.get('/admins/:id/permissions', controller.getPermissions);

  // PATCH /internal/admins/:id/touch-login — called after successful login
  router.patch('/admins/:id/touch-login', controller.touchLogin);

  return router;
}
