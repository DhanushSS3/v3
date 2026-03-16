-- =============================================================================
-- analytics_db — Initial Migration  (requires TimescaleDB extension)
-- Run via pgAdmin Query Tool connected to analytics_db
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ─────────────────────────────────────────────────────────────────────────────
-- Closed Orders — CQRS read-side replica
-- NOTE: TimescaleDB rule: unique indexes MUST include the partitioning column.
-- So (order_id) alone cannot be unique — we use (order_id, closed_at).
-- This is fine in practice: an order only closes once, so closed_at is unique
-- per order_id anyway.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE closed_orders (
  order_id          TEXT             NOT NULL,
  user_id           UUID             NOT NULL,
  user_type         TEXT             NOT NULL,
  account_type      TEXT             NOT NULL,
  symbol            TEXT             NOT NULL,
  order_type        TEXT             NOT NULL,
  volume            NUMERIC(12, 4)   NOT NULL,
  open_price        NUMERIC(18, 8)   NOT NULL,
  close_price       NUMERIC(18, 8)   NOT NULL,
  stop_loss         NUMERIC(18, 8),
  take_profit       NUMERIC(18, 8),
  close_reason      TEXT             NOT NULL,
  open_commission   NUMERIC(18, 6)   NOT NULL DEFAULT 0,
  close_commission  NUMERIC(18, 6)   NOT NULL DEFAULT 0,
  swap              NUMERIC(18, 6)   NOT NULL DEFAULT 0,
  gross_pnl         NUMERIC(18, 6)   NOT NULL,
  net_pnl           NUMERIC(18, 6)   NOT NULL,
  lp_provider_id    UUID,
  execution_mode    TEXT,
  group_name        TEXT,
  mam_order_id      UUID,
  copy_source_id    UUID,
  opened_at         TIMESTAMPTZ      NOT NULL,
  closed_at         TIMESTAMPTZ      NOT NULL
);

SELECT create_hypertable('closed_orders', 'closed_at',
  chunk_time_interval => INTERVAL '1 week'
);

-- ✅ TimescaleDB requires partitioning col (closed_at) in any unique index
CREATE UNIQUE INDEX idx_co_order_unique ON closed_orders (order_id, closed_at);
-- Lookup by user
CREATE INDEX idx_co_user   ON closed_orders (user_id, user_type, closed_at DESC);
CREATE INDEX idx_co_symbol ON closed_orders (symbol, closed_at DESC);
CREATE INDEX idx_co_mam    ON closed_orders (mam_order_id, closed_at DESC) WHERE mam_order_id IS NOT NULL;
CREATE INDEX idx_co_copy   ON closed_orders (copy_source_id, closed_at DESC) WHERE copy_source_id IS NOT NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- Portfolio Snapshots — daily EOD per user
-- Primary key (user_id, snapshot_date) — snapshot_date IS the partition col ✅
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE portfolio_snapshots (
  user_id           UUID             NOT NULL,
  user_type         TEXT             NOT NULL,
  snapshot_date     DATE             NOT NULL,
  balance           NUMERIC(18, 6)   NOT NULL,
  equity            NUMERIC(18, 6)   NOT NULL,
  margin_used       NUMERIC(18, 6)   NOT NULL DEFAULT 0,
  free_margin       NUMERIC(18, 6)   NOT NULL,
  floating_pnl      NUMERIC(18, 6)   NOT NULL DEFAULT 0,
  closed_pnl_today  NUMERIC(18, 6)   NOT NULL DEFAULT 0,
  open_orders       INTEGER          NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, snapshot_date)
);

SELECT create_hypertable('portfolio_snapshots', 'snapshot_date',
  chunk_time_interval => INTERVAL '1 month'
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Market Candles — 1-min OHLCV, partitioned by day
-- No unique constraints → no TimescaleDB conflict ✅
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE market_candles (
  symbol    TEXT           NOT NULL,
  interval  TEXT           NOT NULL DEFAULT '1m',
  open      NUMERIC(18, 8) NOT NULL,
  high      NUMERIC(18, 8) NOT NULL,
  low       NUMERIC(18, 8) NOT NULL,
  close     NUMERIC(18, 8) NOT NULL,
  volume    NUMERIC(18, 4) NOT NULL DEFAULT 0,
  ts        TIMESTAMPTZ    NOT NULL   -- candle open time
);

SELECT create_hypertable('market_candles', 'ts',
  partitioning_column  => 'symbol',
  number_partitions    => 8,
  chunk_time_interval  => INTERVAL '1 day'
);

CREATE INDEX idx_candles ON market_candles (symbol, interval, ts DESC);

-- Daily candles — regular table (no hypertable, kept permanent)
CREATE TABLE market_candles_daily (
  symbol      TEXT           NOT NULL,
  open        NUMERIC(18, 8) NOT NULL,
  high        NUMERIC(18, 8) NOT NULL,
  low         NUMERIC(18, 8) NOT NULL,
  close       NUMERIC(18, 8) NOT NULL,
  volume      NUMERIC(18, 4) NOT NULL DEFAULT 0,
  trade_date  DATE           NOT NULL,
  PRIMARY KEY (symbol, trade_date)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- User Activity Journal — MT5-style log per user
-- Hypertable by event_time, no unique constraints ✅
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE user_activity_journal (
  id            BIGSERIAL    NOT NULL,
  user_id       UUID         NOT NULL,
  user_type     TEXT         NOT NULL,
  event_time    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  source        TEXT         NOT NULL CHECK (source IN (
                               'Terminal','Network','Order','Auth',
                               'System','Admin','Risk','Bonus'
                             )),
  event_type    TEXT         NOT NULL,
  severity      TEXT         NOT NULL DEFAULT 'info'
                             CHECK (severity IN ('info','warning','error','critical')),
  message       TEXT         NOT NULL,
  reference_id  TEXT,
  ip_address    TEXT,
  device_id     TEXT,
  metadata      JSONB        NOT NULL DEFAULT '{}'
);

SELECT create_hypertable('user_activity_journal', 'event_time',
  chunk_time_interval => INTERVAL '1 day'
);

CREATE INDEX idx_journal_user   ON user_activity_journal (user_id, user_type, event_time DESC);
CREATE INDEX idx_journal_source ON user_activity_journal (source, event_time DESC);
CREATE INDEX idx_journal_ref    ON user_activity_journal (reference_id) WHERE reference_id IS NOT NULL;
CREATE INDEX idx_journal_sev    ON user_activity_journal (severity, event_time DESC) WHERE severity IN ('error','critical');

-- Uncomment in production after confirming TimescaleDB:
-- SELECT add_retention_policy('user_activity_journal', INTERVAL '1 year');
-- SELECT add_retention_policy('market_candles', INTERVAL '2 years');
