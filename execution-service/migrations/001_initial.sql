-- =============================================================================
-- execution_db — Initial Migration
-- Run with: psql $EXECUTION_DATABASE_URL -f 001_initial.sql
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────────────────────────────────────
-- Provider Callbacks — immutable log of every callback received from LP
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE provider_callbacks (
  id               BIGSERIAL    NOT NULL,
  lp_provider_id   UUID,
  lifecycle_id     TEXT         NOT NULL,
  order_id         TEXT,
  id_type          TEXT,
  ord_status       TEXT         NOT NULL,
  avg_price        NUMERIC(18, 8),
  cum_qty          NUMERIC(12, 4),
  exec_id          TEXT,
  raw_payload      JSONB        NOT NULL,
  received_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  processed_at     TIMESTAMPTZ,
  processing_error TEXT
) PARTITION BY RANGE (received_at);

CREATE TABLE provider_callbacks_2025 PARTITION OF provider_callbacks
  FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
CREATE TABLE provider_callbacks_2026 PARTITION OF provider_callbacks
  FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

CREATE INDEX idx_callbacks_lifecycle ON provider_callbacks (lifecycle_id);
CREATE INDEX idx_callbacks_order     ON provider_callbacks (order_id, received_at) WHERE order_id IS NOT NULL;
CREATE INDEX idx_callbacks_unproc    ON provider_callbacks (id) WHERE processed_at IS NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- Provider Send Log — immutable log of every outbound message to LP
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE provider_send_log (
  id               BIGSERIAL   NOT NULL,
  lp_provider_id   UUID,
  lifecycle_id     TEXT        NOT NULL,
  order_id         TEXT        NOT NULL,
  id_type          TEXT        NOT NULL,
  action           TEXT        NOT NULL CHECK (action IN (
                                 'open', 'close', 'cancel', 'modify',
                                 'place_sl', 'place_tp', 'cancel_sl', 'cancel_tp'
                               )),
  payload          JSONB       NOT NULL,
  sent_via         TEXT,
  sent_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ack_received_at  TIMESTAMPTZ
) PARTITION BY RANGE (sent_at);

CREATE TABLE provider_send_log_2025 PARTITION OF provider_send_log
  FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
CREATE TABLE provider_send_log_2026 PARTITION OF provider_send_log
  FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

CREATE INDEX idx_send_log_lifecycle ON provider_send_log (lifecycle_id);
CREATE INDEX idx_send_log_order     ON provider_send_log (order_id, sent_at);

-- ─────────────────────────────────────────────────────────────────────────────
-- Execution Worker Heartbeats — liveness tracking per Execution worker pod
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE execution_worker_heartbeats (
  worker_name   TEXT        PRIMARY KEY,
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  host          TEXT,
  pid           INTEGER,
  stats         JSONB       NOT NULL DEFAULT '{}'
);
