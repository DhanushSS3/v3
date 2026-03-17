import { PrismaClient, Prisma, AdminRole as PrismaAdminRole } from '@prisma/client';
import { IAdminRepository } from './IAdminRepository';
import {
  Admin,
  AdminAuthContext,
  AdminPermissionsContext,
  CreateAdminInput,
  UpdateAdminInput,
  PaginationOptions,
  PagedResult,
  AuditLogEntry,
} from '../modules/admin/admin.types';

// ── Single Responsibility: only handles DB operations for Admins ──────────────

export class AdminRepository implements IAdminRepository {
  constructor(
    private readonly db: PrismaClient,
    private readonly readDb: PrismaClient,
  ) {}

  // ── Private mapper ─────────────────────────────────────────────────────────

  private mapAdmin(row: {
    id: string; email: string; passwordHash: string; fullName: string;
    role: string; permissions: string[]; isActive: boolean;
    lastLoginAt: Date | null; createdAt: Date; updatedAt: Date;
  }): Admin {
    return {
      id:           row.id,
      email:        row.email,
      passwordHash: row.passwordHash,
      fullName:     row.fullName,
      role:         row.role as Admin['role'],
      permissions:  row.permissions,
      isActive:     row.isActive,
      lastLoginAt:  row.lastLoginAt,
      createdAt:    row.createdAt,
      updatedAt:    row.updatedAt,
    };
  }

  // ── Auth ───────────────────────────────────────────────────────────────────

  async findByEmail(email: string): Promise<AdminAuthContext | null> {
    return this.readDb.adminUser.findUnique({
      where: { email },
      select: { id: true, email: true, passwordHash: true, isActive: true },
    });
  }

  async findPermissionsById(id: string): Promise<AdminPermissionsContext | null> {
    const admin = await this.readDb.adminUser.findUnique({
      where: { id },
      select: { email: true, permissions: true },
    });
    if (!admin) return null;

    return {
      permissions:   admin.permissions,
      accountNumber: `ADMIN-${admin.email}`,
    };
  }

  // ── CRUD ───────────────────────────────────────────────────────────────────

  async findById(id: string): Promise<Admin | null> {
    const row = await this.readDb.adminUser.findUnique({ where: { id } });
    return row ? this.mapAdmin(row) : null;
  }

  async findAll({ page, limit }: PaginationOptions): Promise<PagedResult<Admin>> {
    const skip = (page - 1) * limit;
    const [rows, total] = await this.readDb.$transaction([
      this.readDb.adminUser.findMany({
        skip, take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      this.readDb.adminUser.count(),
    ]);

    return {
      data:       rows.map((r) => this.mapAdmin(r)),
      total,
      page,
      totalPages: Math.ceil(total / limit),
    };
  }

  async create(input: CreateAdminInput): Promise<Admin> {
    const row = await this.db.adminUser.create({
      data: {
        email:        input.email,
        passwordHash: input.passwordHash,
        fullName:     input.fullName,
        role:         input.role as PrismaAdminRole,
        permissions:  input.permissions,
      },
    });
    return this.mapAdmin(row);
  }

  async update(id: string, input: UpdateAdminInput): Promise<Admin> {
    const row = await this.db.adminUser.update({
      where: { id },
      data: {
        ...(input.fullName    !== undefined && { fullName:    input.fullName }),
        ...(input.role        !== undefined && { role:        input.role as PrismaAdminRole }),
        ...(input.permissions !== undefined && { permissions: input.permissions }),
        ...(input.isActive    !== undefined && { isActive:    input.isActive }),
      },
    });
    return this.mapAdmin(row);
  }

  async softDelete(id: string): Promise<void> {
    await this.db.adminUser.update({
      where: { id },
      data:  { isActive: false },
    });
  }

  async touchLastLogin(id: string): Promise<void> {
    await this.db.adminUser.update({
      where: { id },
      data:  { lastLoginAt: new Date() },
    });
  }

  // ── Audit ──────────────────────────────────────────────────────────────────

  async createAuditLog(entry: AuditLogEntry): Promise<void> {
    await this.db.auditLog.create({
      data: {
        adminId:     entry.adminId,
        action:      entry.action,
        targetType:  entry.targetType,
        targetId:    entry.targetId,
        beforeState: (entry.beforeState as Prisma.InputJsonValue) ?? Prisma.JsonNull,
        afterState:  (entry.afterState  as Prisma.InputJsonValue) ?? Prisma.JsonNull,
        // exactOptionalPropertyTypes: only spread when defined so field is never explicitly undefined
        ...(entry.ipAddress !== undefined && { ipAddress: entry.ipAddress }),
      },
    });
  }
}
