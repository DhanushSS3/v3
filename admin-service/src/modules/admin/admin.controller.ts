import { Request, Response } from 'express';
import { AdminService } from './admin.service';
import { UpdateAdminInput, CreateAdminInput } from './admin.types';

// ── Thin controller: no business logic — only HTTP ↔ service translation ──────
// ── Single Responsibility: handle HTTP (parse req, call service, send res) ────

export class AdminController {
  constructor(private readonly service: AdminService) {
    // Bind all methods so they work as Express route callbacks
    this.getById           = this.getById.bind(this);
    this.list              = this.list.bind(this);
    this.create            = this.create.bind(this);
    this.update            = this.update.bind(this);
    this.deactivate        = this.deactivate.bind(this);
    this.getAuthContext    = this.getAuthContext.bind(this);
    this.getPermissions    = this.getPermissions.bind(this);
    this.touchLogin        = this.touchLogin.bind(this);
  }

  // ── Admin panel endpoints ─────────────────────────────────────────────────

  async list(req: Request, res: Response): Promise<void> {
    const page  = Number(req.query['page'])  || 1;
    const limit = Number(req.query['limit']) || 20;
    const result = await this.service.listAdmins(page, limit);
    res.json({ success: true, data: result });
  }

  async getById(req: Request, res: Response): Promise<void> {
    const admin = await this.service.getAdminById(req.params['id']!);
    res.json({ success: true, data: admin });
  }

  async create(req: Request, res: Response): Promise<void> {
    const input  = req.body as CreateAdminInput;
    const callerId = req.headers['x-caller-id'] as string;
    const ip     = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip;
    const admin  = await this.service.createAdmin(input, callerId ?? 'system', ip);
    res.status(201).json({ success: true, data: admin });
  }

  async update(req: Request, res: Response): Promise<void> {
    const input    = req.body as UpdateAdminInput;
    const callerId = req.headers['x-caller-id'] as string;
    const ip       = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip;
    const admin    = await this.service.updateAdmin(req.params['id']!, input, callerId ?? 'system', ip);
    res.json({ success: true, data: admin });
  }

  async deactivate(req: Request, res: Response): Promise<void> {
    const callerId = req.headers['x-caller-id'] as string;
    const ip       = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip;
    await this.service.deactivateAdmin(req.params['id']!, callerId ?? 'system', ip);
    res.json({ success: true, message: 'Admin deactivated' });
  }

  // ── Internal endpoints (called by auth-service only) ──────────────────────

  async getAuthContext(req: Request, res: Response): Promise<void> {
    const { email } = req.body as { email: string };
    const ctx = await this.service.getAuthContext(email);
    res.json(ctx);
  }

  async getPermissions(req: Request, res: Response): Promise<void> {
    const ctx = await this.service.getPermissionsContext(req.params['id']!);
    res.json(ctx);
  }

  async touchLogin(req: Request, res: Response): Promise<void> {
    await this.service.touchLastLogin(req.params['id']!);
    res.json({ success: true });
  }
}
