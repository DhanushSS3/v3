import { Kafka, EachMessagePayload } from 'kafkajs';
import { config } from '../config/env';
import { logger } from './logger';
import { registerLiveUserFromKafka, registerDemoUserFromKafka } from '../modules/user/user.service';

// ─────────────────────────────────────────────────────────────────────────────
// Kafka Consumer
//
// Design decisions:
//   - Consumer connects with retry: if Kafka is not up yet, retries with
//     exponential back-off (up to 5 min) instead of crashing the service.
//   - Topic subscription uses `allowAutoTopicCreation: false` at the broker
//     level (set in Kafka config) but we handle the "topic not found" error
//     gracefully here with a retry loop.
//   - Per-message errors are swallowed (logged only) to avoid poison-pill
//     crashing the entire consumer group.
// ─────────────────────────────────────────────────────────────────────────────

const kafka = new Kafka({
  clientId: config.kafkaClientId,
  brokers:  config.kafkaBrokers,
  retry: {
    // KafkaJS will retry connection/metadata errors automatically
    initialRetryTime: 300,
    retries:          20,      // ~20 attempts over ~5 min total with back-off
  },
});

const consumer = kafka.consumer({
  groupId:                      config.kafkaGroupId,
  sessionTimeout:               30_000,
  heartbeatInterval:            3_000,
  maxWaitTimeInMs:              500,
  retry: { retries: 10 },
});

// ── Message router ────────────────────────────────────────────────────────────

async function handleMessage({ topic, message }: EachMessagePayload): Promise<void> {
  const raw = message.value?.toString();
  if (!raw) return;

  let event: { type?: string; [key: string]: unknown };
  try {
    event = JSON.parse(raw) as { type?: string; [key: string]: unknown };
  } catch {
    logger.warn({ topic, raw }, 'Failed to parse Kafka message — skipping');
    return;
  }

  logger.info({ topic, type: event.type }, 'Kafka event received');

  switch (event.type) {
    case 'LIVE_USER_REGISTER':
      await registerLiveUserFromKafka(event);
      break;
    case 'DEMO_USER_REGISTER':
      await registerDemoUserFromKafka(event);
      break;
    default:
      logger.debug({ type: event.type }, 'Unhandled event type — ignoring');
  }
}

// ── Start with retry for missing topics ──────────────────────────────────────

async function subscribeWithRetry(
  topic: string,
  maxAttempts = 12,
  delayMs     = 5_000,
): Promise<void> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await consumer.subscribe({ topic, fromBeginning: false });
      logger.info({ topic }, 'Subscribed to Kafka topic');
      return;
    } catch (err) {
      const isTopicMissing =
        err instanceof Error &&
        (err.message.includes('does not host this topic') ||
          err.message.includes('UNKNOWN_TOPIC') ||
          err.message.includes('LEADER_NOT_AVAILABLE'));

      if (isTopicMissing && attempt < maxAttempts) {
        logger.warn(
          { topic, attempt, maxAttempts, retryIn: `${delayMs / 1000}s` },
          'Kafka topic not found yet — will retry. Run: npm run infra:up to create topics.',
        );
        await new Promise((r) => setTimeout(r, delayMs));
      } else {
        throw err; // Not a missing-topic error, or exhausted retries
      }
    }
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

export async function startKafkaConsumer(): Promise<void> {
  await consumer.connect();

  // Retry subscribe so the service starts even if Kafka-init hasn't created
  // the topic yet (e.g. first docker compose up before kafka-init finishes).
  await subscribeWithRetry('user.register');

  await consumer.run({
    eachMessage: async (payload) => {
      try {
        await handleMessage(payload);
      } catch (err) {
        // Log but never throw — prevents one bad message from killing the consumer
        logger.error({ err, topic: payload.topic }, 'Error processing Kafka message');
      }
    },
  });

  logger.info('Kafka consumer running on topic: user.register');
}

export async function stopKafkaConsumer(): Promise<void> {
  await consumer.disconnect();
}
