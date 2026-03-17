import { z } from 'zod';
import * as dotenv from 'dotenv';
dotenv.config();

const schema = z.object({
  port:              z.coerce.number().default(3002),
  nodeEnv:           z.enum(['development', 'production', 'test']).default('development'),

  // Database
  userDatabaseUrl:     z.string().url(),
  userDatabaseUrlRead: z.string().url().optional(),

  // Kafka
  kafkaBrokers:    z.string().transform((v) => v.split(',')),
  kafkaClientId:   z.string().default('user-service'),
  kafkaGroupId:    z.string().default('user-service-group'),

  // Internal comm
  internalSecret:  z.string().min(16),
  allowedOrigins:  z.string().default('http://localhost:3000').transform((v) => v.split(',')),
});

const parsed = schema.safeParse({
  port:              process.env.PORT,
  nodeEnv:           process.env.NODE_ENV,
  userDatabaseUrl:     process.env.USER_DATABASE_URL,
  userDatabaseUrlRead: process.env.USER_DATABASE_URL_READ,
  kafkaBrokers:    process.env.KAFKA_BROKERS,
  kafkaClientId:   process.env.KAFKA_CLIENT_ID,
  kafkaGroupId:    process.env.KAFKA_GROUP_ID,
  internalSecret:  process.env.INTERNAL_SERVICE_SECRET,
  allowedOrigins:  process.env.ALLOWED_ORIGINS,
});

if (!parsed.success) {
  console.error('❌ user-service: Invalid environment variables', parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const config = parsed.data;
