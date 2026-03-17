import { Router } from 'express';
import { z } from 'zod';
import { AdminController } from '../modules/admin/admin.controller';
import { validate, requireInternalSecret } from '../middleware';
import { config } from '../config/env';

// ── Zod schemas ───────────────────────────────────────────────────────────────

const createAdminSchema = z.object({
  email:       z.string().email(),
  passwordHash: z.string().min(8, 'password must be at least 8 chars'),
  fullName:    z.string().min(2).max(100),
  role:        z.enum(['super_admin', 'admin', 'support', 'compliance', 'finance']),
  permissions: z.array(z.string()).default([]),
});

const updateAdminSchema = z.object({
  fullName:    z.string().min(2).max(100).optional(),
  role:        z.enum(['super_admin', 'admin', 'support', 'compliance', 'finance']).optional(),
  permissions: z.array(z.string()).optional(),
  isActive:    z.boolean().optional(),
}).refine(
  (d) => Object.values(d).some((v) => v !== undefined),
  { message: 'At least one field is required' },
);

/**
 * Admin management routes — used by the internal admin panel frontend.
 * Also protected by x-service-secret because there is no public-facing
 * admin panel API. The frontend calls through the order-gateway which
 * attaches the secret.
 *
 * Open/Closed: add new admin panel features by adding routes here
 *              without modifying the service.
 */
export function createAdminManagementRouter(controller: AdminController): Router {
  const router = Router();

  router.use(requireInternalSecret(config.internalSecret));

  // GET  /admins?page=1&limit=20
  router.get('/', controller.list);

  // GET  /admins/:id
  router.get('/:id', controller.getById);

  // POST /admins
  router.post('/', validate(createAdminSchema), controller.create);

  // PATCH /admins/:id
  router.patch('/:id', validate(updateAdminSchema), controller.update);

  // DELETE /admins/:id  (soft-delete: sets isActive=false)
  router.delete('/:id', controller.deactivate);

  return router;
}
