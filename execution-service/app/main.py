from contextlib import asynccontextmanager
from typing import AsyncGenerator

import asyncpg
import structlog
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings

logger = structlog.get_logger()

# ─── Database connection pool ─────────────────────────────────────────────────
_order_pool: asyncpg.Pool | None = None
_execution_pool: asyncpg.Pool | None = None


async def get_order_pool() -> asyncpg.Pool:
    assert _order_pool is not None, "order_db pool not initialized"
    return _order_pool


async def get_execution_pool() -> asyncpg.Pool:
    assert _execution_pool is not None, "execution_db pool not initialized"
    return _execution_pool


# ─── App lifecycle ────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _order_pool, _execution_pool

    logger.info("execution-service starting", env=settings.ENV)

    _order_pool = await asyncpg.create_pool(
        dsn=settings.ORDER_DATABASE_URL,
        min_size=5,
        max_size=20,
        command_timeout=30,
    )
    _execution_pool = await asyncpg.create_pool(
        dsn=settings.EXECUTION_DATABASE_URL,
        min_size=5,
        max_size=20,
        command_timeout=30,
    )
    logger.info("Database pools connected")

    yield  # service runs here

    if _order_pool:
        await _order_pool.close()
    if _execution_pool:
        await _execution_pool.close()
    logger.info("execution-service shutdown complete")


# ─── FastAPI app ──────────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title="LiveFXHub Execution Service",
        version="3.0.0",
        docs_url="/docs" if settings.ENV == "development" else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "execution-service"}

    # Routers registered here as they are implemented:
    # from app.api import orders_router, callbacks_router
    # app.include_router(orders_router, prefix="/api/v1/orders")

    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.ENV == "development",
        log_config=None,  # structlog handles logging
    )
