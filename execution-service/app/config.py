from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8001
    ENV: str = "development"
    LOG_LEVEL: str = "INFO"

    # Databases
    ORDER_DATABASE_URL: str       # asyncpg DSN: postgresql://user:pass@host:port/db
    EXECUTION_DATABASE_URL: str

    # Redis
    REDIS_URL: str

    # Kafka
    KAFKA_BROKERS: str = "localhost:9092"
    KAFKA_GROUP_ID: str = "execution-service"

    # RabbitMQ
    RABBITMQ_URL: str = "amqp://lfx:lfx_rabbit_dev@localhost:5672/livefxhub"

    # Internal service
    INTERNAL_SERVICE_SECRET: str

    # Worker concurrency
    WORKER_OPEN_CONCURRENCY: int = 10
    WORKER_CLOSE_CONCURRENCY: int = 10

    @property
    def kafka_broker_list(self) -> list[str]:
        return self.KAFKA_BROKERS.split(",")


settings = Settings()  # type: ignore[call-arg]
