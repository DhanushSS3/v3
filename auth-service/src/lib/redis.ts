import Redis from 'ioredis';
import { config } from '../config/env';
import { logger } from '../lib/logger';

let redisClient: Redis;

function createRedisClient(): Redis {
  const isSingleNode =
    config.redisClusterNodes.length === 1 &&
    config.redisClusterNodes[0]!.host === '127.0.0.1';

  if (isSingleNode) {
    // Local dev: single Redis node
    const node = config.redisClusterNodes[0]!;
    const client = new Redis({ host: node.host, port: node.port, lazyConnect: true });
    client.on('error', (err) => logger.error({ err }, 'Redis error'));
    return client;
  }

  // Production: Redis Cluster
  const cluster = new Redis.Cluster(config.redisClusterNodes, {
    redisOptions: { connectTimeout: 5000 },
    clusterRetryStrategy: (times) => Math.min(100 * times, 3000),
  });
  // Cluster extends Redis — cast is safe for our usage
  return cluster as unknown as Redis;
}

export function getRedis(): Redis {
  if (!redisClient) redisClient = createRedisClient();
  return redisClient;
}

export async function connectRedis(): Promise<void> {
  const client = getRedis();
  await client.connect?.();
  logger.info('Redis connected');
}
