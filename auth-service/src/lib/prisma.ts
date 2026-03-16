import { PrismaClient } from '@prisma/client';
import { config } from '../config/env';

const makeClient = (url: string) =>
  new PrismaClient({
    datasources: { db: { url } },
    log: config.nodeEnv === 'development' ? ['warn', 'error'] : ['error'],
  });

// Write client — points to primary DB
export const prismaWrite = makeClient(config.databaseUrl);

// Read client — points to replica (falls back to primary if not set)
export const prismaRead = makeClient(config.databaseUrlRead);

// Default export is the write client (keeps compatibility with index.ts)
export const prisma = prismaWrite;

export async function connectDB(): Promise<void> {
  await prismaWrite.$connect();
  if (config.databaseUrlRead !== config.databaseUrl) {
    await prismaRead.$connect();
  }
}

export async function disconnectDB(): Promise<void> {
  await prismaWrite.$disconnect();
  await prismaRead.$disconnect();
}
