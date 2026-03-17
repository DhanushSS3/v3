import { z } from 'zod';
import * as dotenv from 'dotenv';
dotenv.config();

const schema = z.object({
  port:              z.coerce.number().default(3003),
  nodeEnv:           z.enum(['development', 'production', 'test']).default('development'),

  // Database
  adminDatabaseUrl:     z.string().url(),
  adminDatabaseUrlRead: z.string().url().optional(),

  // Kafka
  kafkaBrokers:  z.string().transform((v) => v.split(',')),
  kafkaClientId: z.string().default('admin-service'),

  // Internal
  internalSecret: z.string().min(16),
  allowedOrigins: z.string().default('http://localhost:3000').transform((v) => v.split(',')),
});

const parsed = schema.safeParse({
  port:              process.env.PORT,
  nodeEnv:           process.env.NODE_ENV,
  adminDatabaseUrl:     process.env.ADMIN_DATABASE_URL,
  adminDatabaseUrlRead: process.env.ADMIN_DATABASE_URL_READ,
  kafkaBrokers:  process.env.KAFKA_BROKERS,
  kafkaClientId: process.env.KAFKA_CLIENT_ID,
  internalSecret: process.env.INTERNAL_SERVICE_SECRET,
  allowedOrigins: process.env.ALLOWED_ORIGINS,
});

if (!parsed.success) {
  console.error('❌ admin-service: Invalid environment variables', parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const config = parsed.data;
