import 'express-async-errors';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import { pinoHttp } from 'pino-http';
import { config } from './config/env';
import { logger } from './lib/logger';
import { connectDB, disconnectDB } from './lib/prisma';
import { connectRedis } from './lib/redis';
import { disconnectKafka } from './lib/kafka';
import { AppError } from './utils/errors';

// ── Routes ────────────────────────────────────────────────────────────────────
import liveRoutes     from './routes/live.routes';
import demoRoutes     from './routes/demo.routes';
import adminRoutes    from './routes/admin.routes';
import authRoutes     from './routes/auth.routes';
import internalRoutes from './routes/internal.routes';

const app = express();

// ── Security middleware ───────────────────────────────────────────────────────
app.use(helmet());
app.set('trust proxy', 1); // Trust first proxy (nginx) for real IP in X-Forwarded-For
app.use(cors({ origin: config.allowedOrigins, credentials: true }));
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(pinoHttp({ logger }));

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'auth-service', ts: new Date().toISOString() });
});

// ── Route mounting ────────────────────────────────────────────────────────────
app.use('/api/live',           liveRoutes);
app.use('/api/demo',           demoRoutes);
app.use('/api/admin/auth',     adminRoutes);
app.use('/api/auth',           authRoutes);
app.use('/internal/auth',      internalRoutes);

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({ success: false, code: err.code, message: err.message });
    return;
  }
  if (err instanceof SyntaxError) {
    res.status(400).json({ success: false, message: 'Invalid JSON body' });
    return;
  }
  logger.error({ err }, 'Unhandled error');
  res.status(500).json({ success: false, message: 'Internal Server Error' });
});

// ── Bootstrap ─────────────────────────────────────────────────────────────────
async function bootstrap(): Promise<void> {
  await connectDB();
  await connectRedis();
  logger.info('✅ auth_db and Redis connected');

  const server = app.listen(config.port, () => {
    logger.info({ port: config.port }, `🚀 auth-service started on :${config.port}`);
  });

  // ── Graceful shutdown ─────────────────────────────────────────────────────
  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutting down gracefully…');
    server.close(async () => {
      await disconnectDB();
      await disconnectKafka();
      logger.info('auth-service stopped');
      process.exit(0);
    });
    // Force exit after 10s
    setTimeout(() => process.exit(1), 10_000);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT',  () => void shutdown('SIGINT'));
}

bootstrap().catch((err) => {
  logger.error({ err }, '❌ Failed to start auth-service');
  process.exit(1);
});
