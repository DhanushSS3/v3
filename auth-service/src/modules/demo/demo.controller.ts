import { Request, Response } from 'express';
import { registerDemoUser, loginDemoUser } from './demo.service';
import { demoRegisterSchema, demoLoginSchema } from './demo.schema';

export async function registerController(req: Request, res: Response): Promise<void> {
  const input = demoRegisterSchema.parse(req.body);
  const result = await registerDemoUser(input);
  res.status(201).json({ success: true, ...result });
}

export async function loginController(req: Request, res: Response): Promise<void> {
  const input = demoLoginSchema.parse(req.body);
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  const ua = req.headers['user-agent'] ?? '';
  const result = await loginDemoUser(input, ip, ua);
  res.json({ success: true, data: result });
}
