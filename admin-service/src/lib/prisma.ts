import { PrismaClient } from '@prisma/client';
import { logger } from './logger';

export const prismaWrite = new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['error', 'warn'] : ['error'],
});

export const prismaRead = process.env.ADMIN_DATABASE_URL_READ
  ? new PrismaClient({
      datasources: { db: { url: process.env.ADMIN_DATABASE_URL_READ } },
      log: ['error'],
    })
  : prismaWrite;

export async function connectDB(): Promise<void> {
  await prismaWrite.$connect();
  logger.info('admin_db connected');
}

export async function disconnectDB(): Promise<void> {
  await prismaWrite.$disconnect();
  if (prismaRead !== prismaWrite) await prismaRead.$disconnect();
}
