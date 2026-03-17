import Redis from 'ioredis';
import { config } from '../config/env';
import { logger } from '../lib/logger';

let redisClient: Redis | InstanceType<typeof Redis.Cluster>;

/**
 * Returns true when the env is configured as a single-node Redis
 * (local dev: only one node and pointing at 127.0.0.1 or localhost).
 */
function isSingleNodeMode(): boolean {
  return (
    config.redisClusterNodes.length === 1 &&
    (config.redisClusterNodes[0]!.host === '127.0.0.1' ||
      config.redisClusterNodes[0]!.host === 'localhost')
  );
}

function createClient(): Redis | InstanceType<typeof Redis.Cluster> {
  if (isSingleNodeMode()) {
    const node = config.redisClusterNodes[0]!;
    // lazyConnect: true — do NOT auto-connect; we call connect() explicitly in bootstrap
    const client = new Redis({ host: node.host, port: node.port, lazyConnect: true });
    client.on('error', (err: Error) => logger.error({ err }, 'Redis error'));
    return client;
  }

  // Production: Redis Cluster auto-connects on first command; do NOT call .connect()
  const cluster = new Redis.Cluster(config.redisClusterNodes, {
    redisOptions: { connectTimeout: 5_000 },
    clusterRetryStrategy: (times) => Math.min(100 * times, 3_000),
  });
  cluster.on('error', (err: Error) => logger.error({ err }, 'Redis Cluster error'));
  return cluster;
}

export function getRedis(): Redis | InstanceType<typeof Redis.Cluster> {
  if (!redisClient) redisClient = createClient();
  return redisClient;
}

/**
 * Explicitly connect the Redis client.
 * - Single-node (lazyConnect): must call .connect()
 * - Cluster: auto-connects → we just wait for the 'ready' event instead
 */
export async function connectRedis(): Promise<void> {
  const client = getRedis();

  if (isSingleNodeMode()) {
    // Cast is safe — single-node path always returns Redis, not Cluster
    await (client as Redis).connect();
  } else {
    // Cluster: wait for ready (it already started connecting when created)
    await new Promise<void>((resolve, reject) => {
      if ((client as InstanceType<typeof Redis.Cluster>).status === 'ready') {
        resolve();
        return;
      }
      client.once('ready', resolve);
      client.once('error', reject);
    });
  }

  logger.info(
    { mode: isSingleNodeMode() ? 'single-node' : 'cluster' },
    'Redis connected',
  );
}
