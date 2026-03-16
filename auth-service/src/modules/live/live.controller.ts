import { Request, Response } from 'express';
import { registerLiveUser, loginLiveUser } from './live.service';
import { liveRegisterSchema, liveLoginSchema } from './live.schema';

export async function registerController(req: Request, res: Response): Promise<void> {
  const input = liveRegisterSchema.parse(req.body);
  const result = await registerLiveUser(input);
  res.status(201).json({ success: true, ...result });
}

export async function loginController(req: Request, res: Response): Promise<void> {
  const input = liveLoginSchema.parse(req.body);
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  const ua = req.headers['user-agent'] ?? '';
  const result = await loginLiveUser(input, ip, ua);
  res.json({ success: true, data: result });
}
