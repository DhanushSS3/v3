import 'express-async-errors';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import { pinoHttp } from 'pino-http';

// ── Config & Infrastructure ───────────────────────────────────────────────────
import { config } from './config/env';
import { logger } from './lib/logger';
import { connectDB, disconnectDB, prismaWrite, prismaRead } from './lib/prisma';

// ── SOLID DI wiring: instantiate outside of request scope ─────────────────────
import { AdminRepository } from './repositories/AdminRepository';
import { AdminService }    from './modules/admin/admin.service';
import { AdminController } from './modules/admin/admin.controller';

// ── Route factories ───────────────────────────────────────────────────────────
import { createInternalRouter }        from './routes/internal.routes';
import { createAdminManagementRouter } from './routes/admin.routes';

// ── Exception handler ─────────────────────────────────────────────────────────
import { AppError } from './utils/errors';

// ─────────────────────────────────────────────────────────────────────────────
// Dependency Injection — compose the object graph here, in one place
// ─────────────────────────────────────────────────────────────────────────────

const adminRepo       = new AdminRepository(prismaWrite, prismaRead);
const adminService    = new AdminService(adminRepo);
const adminController = new AdminController(adminService);

// ─────────────────────────────────────────────────────────────────────────────
// Express App
// ─────────────────────────────────────────────────────────────────────────────

const app = express();

app.use(helmet());
app.set('trust proxy', 1);
app.use(cors({ origin: config.allowedOrigins, credentials: true }));
app.use(compression());
app.use(express.json({ limit: '512kb' }));
app.use(pinoHttp({ logger }));

// Health endpoint
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'admin-service', ts: new Date().toISOString() });
});

// ── Internal routes (auth-service → admin-service) ───────────────────────────
app.use('/internal', createInternalRouter(adminController));

// ── Admin management routes ───────────────────────────────────────────────────
app.use('/admins', createAdminManagementRouter(adminController));

// 404
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// Global error handler
app.use((
  err:  unknown,
  _req: express.Request,
  res:  express.Response,
  _next: express.NextFunction,
) => {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({ success: false, code: err.code, message: err.message });
    return;
  }
  logger.error({ err }, 'Unhandled error');
  res.status(500).json({ success: false, message: 'Internal Server Error' });
});

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap
// ─────────────────────────────────────────────────────────────────────────────

async function bootstrap(): Promise<void> {
  await connectDB();

  const server = app.listen(config.port, () => {
    logger.info({ port: config.port }, `🚀 admin-service started on :${config.port}`);
  });

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutting down admin-service…');
    server.close(async () => {
      await disconnectDB();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT',  () => void shutdown('SIGINT'));
}

bootstrap().catch((err) => {
  logger.error({ err }, '❌ Failed to start admin-service');
  process.exit(1);
});
