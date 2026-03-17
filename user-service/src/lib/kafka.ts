import { Kafka, EachMessagePayload } from 'kafkajs';
import { config } from '../config/env';
import { logger } from './logger';
import { registerLiveUserFromKafka, registerDemoUserFromKafka } from '../modules/user/user.service';

const kafka = new Kafka({
  clientId: config.kafkaClientId,
  brokers:  config.kafkaBrokers,
});

const consumer = kafka.consumer({ groupId: config.kafkaGroupId });

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

export async function startKafkaConsumer(): Promise<void> {
  await consumer.connect();
  await consumer.subscribe({ topic: 'user.register', fromBeginning: false });

  await consumer.run({
    eachMessage: async (payload) => {
      try {
        await handleMessage(payload);
      } catch (err) {
        logger.error({ err, topic: payload.topic }, 'Error processing Kafka message');
        // Do NOT throw — avoid poison pill crashing the consumer
      }
    },
  });

  logger.info('Kafka consumer running on topic: user.register');
}

export async function stopKafkaConsumer(): Promise<void> {
  await consumer.disconnect();
}
