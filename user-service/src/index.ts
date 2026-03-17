import 'express-async-errors';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import { pinoHttp } from 'pino-http';
import { config } from './config/env';
import { logger } from './lib/logger';
import { connectDB, disconnectDB } from './lib/prisma';
import { startKafkaConsumer, stopKafkaConsumer } from './lib/kafka';
import { AppError } from './utils/errors';
import internalRoutes from './routes/internal.routes';

const app = express();

app.use(helmet());
app.set('trust proxy', 1);
app.use(cors({ origin: config.allowedOrigins, credentials: true }));
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(pinoHttp({ logger }));

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'user-service', ts: new Date().toISOString() });
});

// Internal endpoints only — no public API surface (user reads go through order-gateway)
app.use('/internal', internalRoutes);

// 404
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// Error handler
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({ success: false, code: err.code, message: err.message });
    return;
  }
  logger.error({ err }, 'Unhandled error');
  res.status(500).json({ success: false, message: 'Internal Server Error' });
});

async function bootstrap(): Promise<void> {
  await connectDB();
  await startKafkaConsumer();
  logger.info('user_db + Kafka consumer ready');

  const server = app.listen(config.port, () => {
    logger.info({ port: config.port }, `🚀 user-service started on :${config.port}`);
  });

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutting down user-service…');
    server.close(async () => {
      await stopKafkaConsumer();
      await disconnectDB();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT',  () => void shutdown('SIGINT'));
}

bootstrap().catch((err) => {
  logger.error({ err }, '❌ Failed to start user-service');
  process.exit(1);
});
