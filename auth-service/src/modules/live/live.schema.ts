import { z } from 'zod';

export const liveRegisterSchema = z.object({
  email:        z.string().email(),
  phoneNumber:  z.string().min(7).max(20),
  password:     z.string().min(8, 'Password must be at least 8 characters'),
  groupName:    z.string().default('Standard'),
  country:      z.string().min(2).max(100),
});

export type LiveRegisterInput = z.infer<typeof liveRegisterSchema>;

export const liveLoginSchema = z.object({
  email:             z.string().email(),
  password:          z.string().min(1),
  deviceFingerprint: z.string().optional(),
  deviceLabel:       z.string().optional(), // 'Chrome on Windows 11'
});

export type LiveLoginInput = z.infer<typeof liveLoginSchema>;
