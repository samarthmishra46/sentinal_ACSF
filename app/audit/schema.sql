-- =============================================================================
-- Sentinel audit log — PostgreSQL schema (PRODUCTION TARGET)
-- Owner: Nikhil (Secrets Detector + Audit Log)
--
-- Requirements traced to the policy document's "Audit trail integration with
-- Lex-AML" section and Master Analysis gap R-G4:
--   * Append-only + tamper-evident (no UPDATE/DELETE, ever).
--   * Monotonic ordering (BIGSERIAL `seq`).
--   * 7-year retention to match Lex-AML's existing trail.
--   * Shared structured format (same fields, ISO timestamps, user-identity ref).
--   * AUSTRAC-ready: producible alongside Lex-AML records without reconciliation.
--
-- Apply with:  python scripts/init_audit_db.py --backend pg --dsn <admin dsn>
-- (The application never runs this DDL itself.)
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS sentinel_audit;

-- A dedicated, least-privilege role the application connects as. It can INSERT
-- and SELECT only — never UPDATE/DELETE/TRUNCATE. Password is set out of band.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        CREATE ROLE sentinel_app LOGIN;
    END IF;
END
$$;

-- -----------------------------------------------------------------------------
-- The append-only audit table.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sentinel_audit.audit_log (
    seq               BIGSERIAL PRIMARY KEY,          -- monotonic write order
    request_id        UUID         NOT NULL,
    ts                TIMESTAMPTZ  NOT NULL,           -- ISO-8601 / UTC from app
    user_id           TEXT         NOT NULL,
    role              TEXT         NOT NULL,
    service           TEXT         NOT NULL DEFAULT '',
    prompt_hash       CHAR(64)     NOT NULL,           -- SHA-256 hex; NEVER raw text
    policy_triggered  TEXT         NOT NULL DEFAULT '',-- e.g. 'P-07'
    decision          TEXT         NOT NULL,           -- ALLOW/STOP/REDACT/ESCALATE/ALLOW_CONSTRAIN
    reason            TEXT         NOT NULL DEFAULT '',
    actor_type        TEXT         NOT NULL DEFAULT '',-- A-01 / A-02 / A-03 / A-04
    rule_triggered    TEXT         NOT NULL DEFAULT '',-- e.g. 'R-01'
    latency_ms        DOUBLE PRECISION NOT NULL DEFAULT 0,
    signals           JSONB        NOT NULL DEFAULT '[]'::jsonb,
    policy_version    TEXT         NOT NULL,
    inserted_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- V2 (deferred): tamper-evident SHA-256 hash chain. `prev_hash` would link
    -- each row to its predecessor's `record_hash` so any deletion/rewrite is
    -- detectable. Columns are reserved here so adding the chain in V2 is a
    -- backfill, not a migration of every consumer.
    prev_hash         CHAR(64),
    record_hash       CHAR(64),

    CONSTRAINT decision_known CHECK (
        decision IN ('ALLOW','STOP','REDACT','ESCALATE','ALLOW_CONSTRAIN')
    ),
    CONSTRAINT prompt_hash_is_sha256 CHECK (prompt_hash ~ '^[0-9a-f]{64}$')
);

COMMENT ON TABLE  sentinel_audit.audit_log IS
    'Append-only Sentinel decision log. 7-year retention to match Lex-AML. '
    'Tamper-evident: UPDATE/DELETE are blocked by trigger and revoked privilege.';
COMMENT ON COLUMN sentinel_audit.audit_log.prompt_hash IS
    'SHA-256 of the raw prompt. The raw prompt is never stored (policy P-01/P-06).';

-- -----------------------------------------------------------------------------
-- Indexes the plan calls for: query by time, by user, by decision.
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_audit_ts        ON sentinel_audit.audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user      ON sentinel_audit.audit_log (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_decision  ON sentinel_audit.audit_log (decision);
-- Composite for the common "this user's STOPs over time" review query.
CREATE INDEX IF NOT EXISTS idx_audit_user_decision_ts
    ON sentinel_audit.audit_log (user_id, decision, ts DESC);

-- -----------------------------------------------------------------------------
-- Append-only enforcement #1: a trigger that refuses mutation.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sentinel_audit.deny_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_no_update ON sentinel_audit.audit_log;
CREATE TRIGGER trg_audit_no_update
    BEFORE UPDATE OR DELETE ON sentinel_audit.audit_log
    FOR EACH ROW EXECUTE FUNCTION sentinel_audit.deny_mutation();

-- Append-only enforcement #2: privilege. Defence in depth — even a superuser
-- mistake via the app role is blocked.
REVOKE ALL    ON sentinel_audit.audit_log FROM sentinel_app;
GRANT  INSERT, SELECT ON sentinel_audit.audit_log TO sentinel_app;
GRANT  USAGE  ON SCHEMA sentinel_audit TO sentinel_app;
GRANT  USAGE  ON SEQUENCE sentinel_audit.audit_log_seq_seq TO sentinel_app;
