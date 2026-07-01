-- =============================================================================
-- Sentinel audit log — SQLite schema (DAY 1-2 FALLBACK)
-- Owner: Nikhil (Secrets Detector + Audit Log)
--
-- Same logical shape as schema.sql (PostgreSQL). Per the sprint plan's risk
-- mitigation, SQLite stands in for PostgreSQL on Day 1-2 with zero external
-- dependencies; only the driver changes when we cut over to Postgres. The
-- AuditRecord model and the AsyncAuditLogger interface are identical either way.
--
-- Differences from Postgres, all cosmetic:
--   * seq        -> INTEGER PRIMARY KEY AUTOINCREMENT (monotonic)
--   * ts         -> TEXT (ISO-8601 string, same value the app produces)
--   * signals    -> TEXT (JSON string) instead of JSONB
--   * append-only enforced by triggers raising ABORT (SQLite has no role grants)
-- =============================================================================

PRAGMA journal_mode = WAL;   -- durable, allows concurrent reads during writes

CREATE TABLE IF NOT EXISTS audit_log (
    seq               INTEGER PRIMARY KEY AUTOINCREMENT,  -- monotonic write order
    request_id        TEXT    NOT NULL,
    ts                TEXT    NOT NULL,                    -- ISO-8601 / UTC
    user_id           TEXT    NOT NULL,
    role              TEXT    NOT NULL,
    service           TEXT    NOT NULL DEFAULT '',
    prompt_hash       TEXT    NOT NULL,                    -- SHA-256 hex; NEVER raw
    policy_triggered  TEXT    NOT NULL DEFAULT '',
    decision          TEXT    NOT NULL,
    reason            TEXT    NOT NULL DEFAULT '',
    actor_type        TEXT    NOT NULL DEFAULT '',
    rule_triggered    TEXT    NOT NULL DEFAULT '',
    latency_ms        REAL    NOT NULL DEFAULT 0,
    signals           TEXT    NOT NULL DEFAULT '[]',       -- JSON array string
    policy_version    TEXT    NOT NULL,
    inserted_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),

    -- V2 (deferred) tamper-evident hash chain; reserved, see schema.sql.
    prev_hash         TEXT,
    record_hash       TEXT,

    CHECK (decision IN ('ALLOW','STOP','REDACT','ESCALATE','ALLOW_CONSTRAIN')),
    CHECK (length(prompt_hash) = 64)
);

CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user     ON audit_log (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_log (decision);
CREATE INDEX IF NOT EXISTS idx_audit_user_decision_ts
    ON audit_log (user_id, decision, ts DESC);

-- Append-only enforcement: refuse UPDATE and DELETE. Any attempt aborts the
-- statement with a clear message, making tampering loud rather than silent.
CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not permitted');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted');
END;
