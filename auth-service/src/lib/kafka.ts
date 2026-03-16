import { Kafka, Producer, CompressionTypes } from 'kafkajs';
import { config } from '../config/env';
import { logger } from './logger';

const kafka = new Kafka({
  clientId: config.kafkaClientId,
  brokers: config.kafkaBrokers,
  retry: { retries: 5, initialRetryTime: 300 },
});

let producer: Producer | null = null;

export async function getKafkaProducer(): Promise<Producer> {
  if (!producer) {
    producer = kafka.producer({ allowAutoTopicCreation: false });
    await producer.connect();
    logger.info('Kafka producer connected');
  }
  return producer;
}

export async function publishEvent(
  topic: string,
  key: string,
  payload: Record<string, unknown>,
): Promise<void> {
  try {
    const p = await getKafkaProducer();
    await p.send({
      topic,
      compression: CompressionTypes.GZIP,
      messages: [{ key, value: JSON.stringify({ ...payload, publishedAt: new Date().toISOString() }) }],
    });
  } catch (err) {
    // Non-fatal — log and continue (journal events should not block auth)
    logger.error({ err, topic, key }, 'Failed to publish Kafka event');
  }
}

export async function disconnectKafka(): Promise<void> {
  await producer?.disconnect();
}
