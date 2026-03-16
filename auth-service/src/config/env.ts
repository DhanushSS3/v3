import { z } from 'zod';
import 'dotenv/config';

const schema = z.object({
    PORT:                    z.coerce.number().default(3001),
    NODE_ENV:                z.enum(['development', 'production', 'test']).default('development'),
    // Write DB (primary)
    AUTH_DATABASE_URL:       z.string().url(),
    // Read replica — optional, falls back to write DB if not set
    AUTH_DATABASE_URL_READ:  z.string().url().optional(),
    // Redis cluster — comma-separated "host:port" seed nodes
    // e.g. "10.10.0.3:31001"  (ioredis auto-discovers the other 5 nodes)
    // For local Docker dev: "127.0.0.1:6379"
    REDIS_CLUSTER_NODES:     z.string().default('127.0.0.1:6379'),
    KAFKA_BROKERS:           z.string().default('localhost:9092'),
    KAFKA_CLIENT_ID:         z.string().default('auth-service'),
    JWT_SECRET:              z.string().min(32),
    JWT_EXPIRES_IN:          z.string().default('15m'),
    JWT_REFRESH_EXPIRES_IN:  z.string().default('7d'),
    OTP_EXPIRES_IN_MINUTES:  z.coerce.number().default(10),
    OTP_MAX_ATTEMPTS:        z.coerce.number().default(5),
    TOTP_ENCRYPTION_KEY:     z.string().min(32),
    TRUSTED_DEVICE_DAYS:     z.coerce.number().default(30),
    AUTH_INACTIVITY_2FA_DAYS: z.coerce.number().default(30),
    AUTH_NEW_DEVICE_ALERT:    z.string().default('true'),
    RATE_LIMIT_WINDOW_MS:    z.coerce.number().default(60000),
    RATE_LIMIT_MAX:          z.coerce.number().default(100),
    ALLOWED_ORIGINS:         z.string().default('http://localhost:3000'),
    INTERNAL_SERVICE_SECRET: z.string().min(16).default('change-me-in-production'),
    EMAIL_HOST:              z.string().default('smtp.hostinger.com'),
    EMAIL_PORT:              z.coerce.number().default(465),
    EMAIL_SECURE:            z.string().default('true'),
    EMAIL_USER:              z.string().default('noreply@livehub.com'),
    EMAIL_PASS:              z.string().default(''),
    EMAIL_FROM:              z.string().default('LiveFXHub <noreply@livefhub.com>'),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
    console.error('❌ Invalid environment variables:', parsed.error.flatten().fieldErrors);
    process.exit(1);
}

const d = parsed.data;

// Parse Redis cluster nodes: "10.10.0.3:31001,10.10.0.3:31002" → [{host, port}]
const redisClusterNodes = d.REDIS_CLUSTER_NODES.split(',').map((node) => {
    const [host, portStr] = node.trim().split(':');
    return { host: host!, port: parseInt(portStr ?? '6379', 10) };
});

export const config = {
    port:               d.PORT,
    nodeEnv:            d.NODE_ENV,
    databaseUrl:        d.AUTH_DATABASE_URL,
    databaseUrlRead:    d.AUTH_DATABASE_URL_READ ?? d.AUTH_DATABASE_URL,
    redisClusterNodes,
    kafkaBrokers:       d.KAFKA_BROKERS.split(','),
    kafkaClientId:      d.KAFKA_CLIENT_ID,
    jwtSecret:          d.JWT_SECRET,
    jwtExpiresIn:       d.JWT_EXPIRES_IN,
    jwtRefreshExpiresIn: d.JWT_REFRESH_EXPIRES_IN,
    otpExpiresInMinutes: d.OTP_EXPIRES_IN_MINUTES,
    otpMaxAttempts:     d.OTP_MAX_ATTEMPTS,
    totpEncryptionKey:  d.TOTP_ENCRYPTION_KEY,
    trustedDeviceDays:  d.TRUSTED_DEVICE_DAYS,
    inactivity2faDays:  d.AUTH_INACTIVITY_2FA_DAYS,
    newDeviceAlert:     d.AUTH_NEW_DEVICE_ALERT === 'true',
    rateLimitWindowMs:  d.RATE_LIMIT_WINDOW_MS,
    rateLimitMax:       d.RATE_LIMIT_MAX,
    allowedOrigins:     d.ALLOWED_ORIGINS.split(','),
    internalSecret:     d.INTERNAL_SERVICE_SECRET,
    emailHost:          d.EMAIL_HOST,
    emailPort:          d.EMAIL_PORT,
    emailSecure:        d.EMAIL_SECURE === 'true',
    emailUser:          d.EMAIL_USER,
    emailPass:          d.EMAIL_PASS,
    emailFrom:          d.EMAIL_FROM,
} as const;
