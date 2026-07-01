# Sentinel Audit Log — Subsystem Guide

Owner: **Nikhil** (Secrets Detector + Audit Log). This guide covers the audit-log
subsystem only (`app/audit/`). It is the Day-1 deliverable; the real secrets
detector is Day-2.

## What it is

Every Sentinel decision (ALLOW / STOP / REDACT / ESCALATE / ALLOW_CONSTRAIN)
produces exactly one **`AuditRecord`**, which is written to an **append-only,
tamper-evident** table. The log is the compliance backbone: the policy document
requires it to be queryable alongside Lex-AML's existing audit trail, retained
for **7 years**, and **AUSTRAC-ready**.

Two backends sit behind one interface:

| Backend | Driver | Use | Runs here today? |
|---|---|---|---|
| `SqliteBackend` | stdlib `sqlite3` | Day 1-2 fallback, tests, demo | ✅ yes (no deps) |
| `PostgresBackend` | `asyncpg` | V1 production target (gap R-G4) | needs Postgres + `asyncpg` |

The `AuditRecord` model and `AsyncAuditLogger` API are identical for both —
"only the driver changes."

## The AuditRecord fields (locked Day 1)

`request_id`, `timestamp` (ISO-8601 UTC), `user_id`, `role`, `service`,
`prompt_hash` (SHA-256 — **never the raw prompt**), `policy_triggered`,
`decision`, `reason`, `actor_type` (A-01…A-04), `rule_triggered`, `latency_ms`,
`signals` (list), `policy_version`.

## Quick start

```bash
# 1. Create the local (SQLite) audit DB with the append-only schema:
python scripts/init_audit_db.py --backend sqlite --path ./sentinel_audit.db

# 2. Run the tests (22 of them, no external services needed):
python -m pytest tests/audit -q

# 3. See it work end-to-end (writes 4 sample decisions, runs review queries):
python scripts/audit_demo.py
```

## How callers use it (integration contract for the team)

`Ryan`'s PEP / `Samarth`'s pipeline create a record and hand it to the logger.
Nothing on the request path waits on the database write.

```python
from app.audit import AsyncAuditLogger, AuditRecord, SqliteBackend

logger = AsyncAuditLogger(SqliteBackend("sentinel_audit.db"))
await logger.start()                      # once, at app startup

# Option A — build from primitives (always available, Day 1):
rec = AuditRecord.new(
    user_id="u-aisha", role="Engineer", actor_type="A-01",
    service="risk-scoring", decision="STOP", rule_triggered="R-01",
    policy_triggered="P-01", reason="Customer PII detected",
    prompt=raw_prompt,                    # hashed inside; raw text discarded
    latency_ms=elapsed_ms, signals=["pii:TFN"],
)
await logger.log(rec)

# Option B — build straight from Samarth's Decision + the RequestContext,
# once those exist (duck-typed, no import coupling today):
rec = AuditRecord.from_decision(decision, context, prompt=raw_prompt)
await logger.log(rec)

await logger.stop(drain=True)             # once, at shutdown (flushes the queue)
```

`log_nowait(rec)` is the non-blocking variant for the hot path; it returns
`False` (and increments `logger.dropped`) if the queue is saturated.

### Fail-closed hook (used on Day 3)

`logger.healthy` flips to `False` if the backend starts erroring. The PEP should
read it and **ESCALATE rather than answer un-audited** when the audit store is
down — a decision must never reach the user without a compliance record.

## Append-only / tamper-evidence

Enforced in the database, not the app, so even a stray SQL statement can't
rewrite history:

- **SQLite**: `BEFORE UPDATE` / `BEFORE DELETE` triggers `RAISE(ABORT, …)`.
- **PostgreSQL**: a `BEFORE UPDATE OR DELETE` trigger raises, **and** the app
  role is granted `INSERT, SELECT` only (`UPDATE/DELETE/TRUNCATE` revoked).

`scripts/audit_demo.py` demonstrates a blocked UPDATE at the end of its run.

## Moving to PostgreSQL (Day 3)

```bash
pip install -r requirements-audit.txt
python scripts/init_audit_db.py --backend pg \
    --dsn postgres://admin:pw@localhost:5432/postgres --db sentinel_audit
```

Then construct the logger with `PostgresBackend(dsn)` instead of `SqliteBackend`.
No other code changes.

## File map

```
app/audit/models.py          AuditRecord, hash_prompt(), validation, factories
app/audit/backends.py        AuditBackend ABC + SqliteBackend + PostgresBackend
app/audit/logger.py          AsyncAuditLogger (asyncio queue + background worker)
app/audit/schema.sql         PostgreSQL DDL (append-only, indexes, 7-yr retention)
app/audit/schema_sqlite.sql  SQLite DDL (same shape, fallback)
scripts/init_audit_db.py     create DB + apply schema (--backend sqlite|pg)
scripts/audit_demo.py        end-to-end demo + the 3 review queries
tests/audit/                 22 unit + integration tests
```

## Deferred (not in this Day-1 slice)

- **Real secrets/credential scanner (R-07)** → Nikhil, Day 2.
- **SHA-256 hash chain** on the log (`prev_hash`/`record_hash` columns are
  reserved in the schema) → V2.
- **Real EIM identity**, **HA Postgres** → V2.
