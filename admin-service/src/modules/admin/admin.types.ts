// ─── Domain Types (no external dependencies) ────────────────────────────────

export type AdminRole = 'super_admin' | 'admin' | 'support' | 'compliance' | 'finance';

export interface Admin {
  id:          string;
  email:       string;
  passwordHash: string;
  fullName:    string;
  role:        AdminRole;
  permissions: string[];
  isActive:    boolean;
  lastLoginAt: Date | null;
  createdAt:   Date;
  updatedAt:   Date;
}

/** Returned when auth-service calls for login — no sensitive data for non-auth use */
export interface AdminAuthContext {
  id:           string;
  email:        string;
  passwordHash: string;
  isActive:     boolean;
}

/** Returned after step 2 login — permissions for JWT payload */
export interface AdminPermissionsContext {
  permissions:   string[];
  accountNumber: string; // always 'ADMIN-<email>' for tracing
}

export interface CreateAdminInput {
  email:       string;
  passwordHash: string;
  fullName:    string;
  role:        AdminRole;
  permissions: string[];
}

export interface UpdateAdminInput {
  fullName?:    string;
  role?:        AdminRole;
  permissions?: string[];
  isActive?:    boolean;
}

export interface PaginationOptions {
  page:  number;
  limit: number;
}

export interface PagedResult<T> {
  data:       T[];
  total:      number;
  page:       number;
  totalPages: number;
}

export interface AuditLogEntry {
  adminId:    string;
  action:     string;
  targetType: string;
  targetId:   string;
  beforeState?: unknown;
  afterState?:  unknown;
  ipAddress?: string;
}
