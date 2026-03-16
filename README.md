# LiveFXHub V3

Microservices trading platform. Each subdirectory is an independent service with its own Git repository and CI/CD pipeline.

## Services

| Service | Language | Database | Port |
|---|---|---|---|
| `auth-service` | Node.js + Prisma | auth_db (5432) | 3001 |
| `user-service` | Node.js + Prisma | user_db (5433) | 3002 |
| `order-gateway` | Node.js + Prisma | order_db (5434) | 3003 |
| `risk-service` | Node.js + Prisma | risk_db (5436) | 3004 |
| `admin-service` | Node.js + Prisma | admin_db (5438) | 3005 |
| `execution-service` | Python + asyncpg | execution_db (5435) + order_db | 8001 |
| `analytics-service` | Python + asyncpg | analytics_db (5437) | 8002 |
| `lp-feed-service` | Python | — (FIX socket) | 8003 |
| `portfolio-service` | Python | — (Redis) | 8004 |
| `notification-service` | Node.js + ws | — | 3006 |

## Local Development

```bash
# Start all infrastructure (Postgres x7, Redis, Kafka, RabbitMQ)
docker compose -f docker-compose.dev.yml up -d

# Run migrations for each Node.js service
cd auth-service && npx prisma migrate dev --name init && cd ..
cd user-service && npx prisma migrate dev --name init && cd ..
cd order-gateway && npx prisma migrate dev --name init && cd ..
cd risk-service && npx prisma migrate dev --name init && cd ..
cd admin-service && npx prisma migrate dev --name init && cd ..

# Start each service (in separate terminals)
cd auth-service && npm run dev
cd user-service && npm run dev
# etc.
```

## Kafka Topics

See `docker-compose.dev.yml` → `kafka-init` service for all 14 topic definitions.

## Architecture

See [`../Livefxhub-Backend/livefxhub_v2_master_architecture.md`](../Livefxhub-Backend/livefxhub_v2_master_architecture.md) for full architecture documentation.
