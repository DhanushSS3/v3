import Redis from 'ioredis';
import { config } from '../config/env';
import { logger } from '../lib/logger';

// ─────────────────────────────────────────────────────────────────────────────
// Redis NAT Map
//
// Problem: Redis Cluster nodes advertise their *internal* IPs (10.50.0.x) in
// CLUSTER NODES gossip. When ioredis receives this gossip it tries to connect
// to those internal IPs directly — which fails from outside the k8s network.
//
// Solution: Use ioredis `natMap` to rewrite internal host:port → external VPN
// host:port before making any connection attempt.
//
// Mapping (verified via `redis-cli CLUSTER NODES` on each VPN port):
//   10.50.0.184:6379  →  185.131.54.146:31010  (master, slots 0-5460)
//   10.50.0.186:6379  →  185.131.54.146:31011  (master, slots 5461-10922)
//   10.50.0.188:6379  →  185.131.54.146:31003  (master, slots 10923-16383)
//   10.50.0.190:6379  →  185.131.54.146:31009  (slave of 10.50.0.188)
//   10.50.0.192:6379  →  185.131.54.146:31007  (slave of 10.50.0.186)
//   10.50.0.194:6379  →  185.131.54.146:31008  (slave of 10.50.0.184)
//
// For local dev (127.0.0.1): natMap is empty — no rewriting needed.
// ─────────────────────────────────────────────────────────────────────────────

type NatMap = Record<string, { host: string; port: number }>;

/**
 * Build natMap from REDIS_NAT_MAP env var (JSON) or fall back to the
 * hardcoded VPN mapping.
 *
 * Env var format (set this in .env or k8s ConfigMap):
 *   REDIS_NAT_MAP='{"10.50.0.184:6379":{"host":"185.131.54.146","port":31010},...}'
 */
function buildNatMap(): NatMap {
  // Prefer explicit env var (makes it easy to change without code deploy)
  if (process.env.REDIS_NAT_MAP) {
    try {
      return JSON.parse(process.env.REDIS_NAT_MAP) as NatMap;
    } catch {
      logger.warn('REDIS_NAT_MAP is set but could not be parsed as JSON — ignoring');
    }
  }
  return {};
}

let redisClient: Redis | InstanceType<typeof Redis.Cluster>;

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
    const client = new Redis({ host: node.host, port: node.port, lazyConnect: true });
    client.on('error', (err: Error) => logger.error({ err }, 'Redis error'));
    return client;
  }

  const natMap = buildNatMap();
  const hasNatMap = Object.keys(natMap).length > 0;

  if (hasNatMap) {
    logger.info({ entries: Object.keys(natMap).length }, 'Redis Cluster natMap active');
  }

  /**
   * Key cluster options for NAT traversal:
   *   natMap          — rewrites internal IPs from CLUSTER NODES gossip
   *   slotsRefreshTimeout — how long to wait for slot refresh before error
   *   clusterRetryStrategy — exponential back-off up to 3 s
   *   enableReadyCheck — wait until cluster is actually ready
   */
  const cluster = new Redis.Cluster(config.redisClusterNodes, {
    ...(hasNatMap && { natMap }),
    slotsRefreshTimeout:  5_000,
    redisOptions: {
      connectTimeout:  6_000,
      commandTimeout:  5_000,
      enableReadyCheck: true,
    },
    clusterRetryStrategy: (times) => {
      if (times > 10) return null; // stop retrying after 10 attempts
      return Math.min(200 * times, 3_000);
    },
  });

  cluster.on('error',   (err: Error) => logger.error({ err }, 'Redis Cluster error'));
  cluster.on('connect', ()           => logger.debug('Redis Cluster connecting'));
  cluster.on('+node',   (node)       => logger.debug({ node: `${node.options.host}:${node.options.port}` }, 'Redis Cluster node added'));

  return cluster;
}

export function getRedis(): Redis | InstanceType<typeof Redis.Cluster> {
  if (!redisClient) redisClient = createClient();
  return redisClient;
}

export async function connectRedis(): Promise<void> {
  const client = getRedis();

  if (isSingleNodeMode()) {
    await (client as Redis).connect();
  } else {
    await new Promise<void>((resolve, reject) => {
      const cluster = client as InstanceType<typeof Redis.Cluster>;
      if (cluster.status === 'ready') { resolve(); return; }

      // Timeout guard: 15 s should be enough for cluster slot discovery
      const timer = setTimeout(() => reject(new Error('Redis Cluster ready timeout (15 s)')), 15_000);

      cluster.once('ready', () => { clearTimeout(timer); resolve(); });
      cluster.once('error', (err) => { clearTimeout(timer); reject(err); });
    });
  }

  logger.info(
    { mode: isSingleNodeMode() ? 'single-node' : 'cluster' },
    'Redis connected',
  );
}

export async function disconnectRedis(): Promise<void> {
  if (redisClient) await redisClient.quit();
}
