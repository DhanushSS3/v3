import bcrypt from 'bcryptjs';
import { IAdminRepository } from '../../repositories/IAdminRepository';
import { AppError } from '../../utils/errors';
import {
  Admin,
  AdminAuthContext,
  AdminPermissionsContext,
  CreateAdminInput,
  PagedResult,
  UpdateAdminInput,
} from './admin.types';

// ── Single Responsibility: pure business logic — no Prisma, no HTTP ───────────
// ── Dependency Inversion: depends on IAdminRepository interface, not PrismaClient ─

const SALT_ROUNDS = 12;

export class AdminService {
  constructor(private readonly repo: IAdminRepository) {}

  // ── Internal auth: called by auth-service HTTP endpoints ─────────────────

  async getAuthContext(email: string): Promise<AdminAuthContext> {
    const admin = await this.repo.findByEmail(email);
    if (!admin) throw new AppError('ADMIN_NOT_FOUND', 404);
    return admin;
  }

  async getPermissionsContext(id: string): Promise<AdminPermissionsContext> {
    const ctx = await this.repo.findPermissionsById(id);
    if (!ctx) throw new AppError('ADMIN_NOT_FOUND', 404);
    return ctx;
  }

  async touchLastLogin(id: string): Promise<void> {
    await this.repo.touchLastLogin(id);
  }

  // ── Admin management: called by admin panel endpoints ────────────────────

  async createAdmin(input: CreateAdminInput, createdById: string, ip?: string): Promise<Admin> {
    const existing = await this.repo.findByEmail(input.email);
    if (existing) throw new AppError('ADMIN_EMAIL_TAKEN', 409, 'An admin with that email already exists');

    const passwordHash = await bcrypt.hash(input.passwordHash, SALT_ROUNDS);
    const admin = await this.repo.create({ ...input, passwordHash });

    await this.repo.createAuditLog({
      adminId:    createdById,
      action:     'ADMIN_CREATE',
      targetType: 'admin',
      targetId:   admin.id,
      afterState: { email: admin.email, role: admin.role },
      ...(ip && { ipAddress: ip }),
    });

    return admin;
  }

  async getAdminById(id: string): Promise<Admin> {
    const admin = await this.repo.findById(id);
    if (!admin) throw new AppError('ADMIN_NOT_FOUND', 404);
    return admin;
  }

  async listAdmins(page: number, limit: number): Promise<PagedResult<Admin>> {
    const safePage  = Math.max(1, page);
    const safeLimit = Math.min(100, Math.max(1, limit));
    return this.repo.findAll({ page: safePage, limit: safeLimit });
  }

  async updateAdmin(
    id: string,
    input: UpdateAdminInput,
    updatedById: string,
    ip?: string,
  ): Promise<Admin> {
    const before = await this.getAdminById(id);
    const after  = await this.repo.update(id, input);

    await this.repo.createAuditLog({
      adminId:     updatedById,
      action:      'ADMIN_UPDATE',
      targetType:  'admin',
      targetId:    id,
      beforeState: { role: before.role, permissions: before.permissions, isActive: before.isActive },
      afterState:  { role: after.role,  permissions: after.permissions,  isActive: after.isActive  },
      ...(ip && { ipAddress: ip }),
    });

    return after;
  }

  async deactivateAdmin(id: string, deactivatedById: string, ip?: string): Promise<void> {
    if (id === deactivatedById) throw new AppError('CANNOT_DEACTIVATE_SELF', 400);
    await this.getAdminById(id); // throws if not found

    await this.repo.softDelete(id);
    await this.repo.createAuditLog({
      adminId:    deactivatedById,
      action:     'ADMIN_DEACTIVATE',
      targetType: 'admin',
      targetId:   id,
      ...(ip && { ipAddress: ip }),
    });
  }
}
