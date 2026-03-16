import { z } from 'zod';

export const demoRegisterSchema = z.object({
  email:         z.string().email(),
  password:      z.string().min(8),
  name:          z.string().min(2).max(100),
  phoneNumber:   z.string().min(7).max(20),
  country:       z.string().min(2).max(100),
  city:          z.string().min(2).max(100),
  state:         z.string().optional(),
  groupName:     z.string().default('Standard'),
  currency:      z.string().default('USD'),
  leverage:      z.coerce.number().int().min(1).max(2000).default(100),
  initialBalance: z.coerce.number().min(1).max(1_000_000).default(10000),
});

export const demoLoginSchema = z.object({
  email:    z.string().email(),
  password: z.string().min(1),
});

export type DemoRegisterInput = z.infer<typeof demoRegisterSchema>;
export type DemoLoginInput = z.infer<typeof demoLoginSchema>;
