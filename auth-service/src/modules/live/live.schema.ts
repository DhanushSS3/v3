import { z } from 'zod';

export const liveRegisterSchema = z.object({
  email:           z.string().email(),
  password:        z.string().min(8, 'Password must be at least 8 characters'),
  name:            z.string().min(2).max(100),
  phoneNumber:     z.string().min(7).max(20),
  country:         z.string().min(2).max(100),
  city:            z.string().min(2).max(100),
  state:           z.string().optional(),
  pincode:         z.string().optional(),
  groupName:       z.string().default('Standard'),
  currency:        z.string().default('USD'),
  leverage:        z.coerce.number().int().min(1).max(2000).default(100),
  isSelfTrading:   z.coerce.boolean().default(true),
});

export type LiveRegisterInput = z.infer<typeof liveRegisterSchema>;

export const liveLoginSchema = z.object({
  email:             z.string().email(),
  password:          z.string().min(1),
  deviceFingerprint: z.string().optional(),
  deviceLabel:       z.string().optional(), // 'Chrome on Windows 11'
});

export type LiveLoginInput = z.infer<typeof liveLoginSchema>;
