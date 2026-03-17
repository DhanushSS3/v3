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

// ── Dependency Inversion Principle: Service depends on this interface, not Prisma ──

export interface IAdminRepository {
  // Auth
  findByEmail(email: string): Promise<AdminAuthContext | null>;
  findPermissionsById(id: string): Promise<AdminPermissionsContext | null>;

  // CRUD
  findById(id: string): Promise<Admin | null>;
  findAll(options: PaginationOptions): Promise<PagedResult<Admin>>;
  create(input: CreateAdminInput): Promise<Admin>;
  update(id: string, input: UpdateAdminInput): Promise<Admin>;
  softDelete(id: string): Promise<void>;
  touchLastLogin(id: string): Promise<void>;

  // Audit
  createAuditLog(entry: AuditLogEntry): Promise<void>;
}
