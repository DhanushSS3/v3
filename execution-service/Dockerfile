FROM python:3.12-slim AS base
WORKDIR /app

# Install uv for fast dependency resolution
RUN pip install uv

FROM base AS builder
COPY pyproject.toml ./
RUN uv pip install --system --no-cache .

FROM base AS runner
RUN useradd -m -u 1001 appuser

COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /usr/local/bin /usr/local/bin
COPY app/ ./app/
COPY migrations/ ./migrations/

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
