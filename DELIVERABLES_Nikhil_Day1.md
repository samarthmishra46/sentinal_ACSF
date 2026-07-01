# Nikhil — Day 1 Deliverables: Audit Log + DB Schema

**Sprint:** Sentinel (AI security framework for the Lex-AML assistant) · 4-day V1
prototype · 7-person team coordinated by Deveshi.
**My role:** Secrets Detector + Audit Log (MID-LEVEL).
**This document:** what I built for **Day 1**, why, and how to run it.

---

## 1. What Day 1 asked of me

From the sprint plan (`Sentinel_4Day_Sprint_Plan.html`), my Day-1 card was
**"Audit Log + DB Schema"**:

- Agree the `AuditRecord` fields (locked with Deveshi on Day 1 morning).
- Write `app/audit/models.py` — the `AuditRecord` dataclass.
- Set up the database and write `app/audit/schema.sql` — append-only table,
  monotonic sequence, indexes on `(ts, user_id, decision)`.
- Write `app/audit/logger.py` — an async writer (asyncio queue + background
  worker → DB).
- Write unit tests.

The **real secrets/credential scanner (R-07)** is explicitly a **Day-2** task, so
it is intentionally **not** in this delivery.

**Day-1 gate:** a request travels through to a `Decision` and an `AuditRecord` is
written to the database — full plumbing, no detection logic yet.

## 2. What I built

A complete, tested audit-log subsystem under `app/audit/`, plus setup/demo
scripts, tests, and docs.

| File | Purpose |
|---|---|
| `app/audit/models.py` | `AuditRecord` (the 14 locked fields), `hash_prompt()`, validation, and two factories (`new`, `from_decision`). |
| `app/audit/backends.py` | `AuditBackend` interface + `SqliteBackend` (stdlib, runs everywhere) + `PostgresBackend` (asyncpg, production). |
| `app/audit/logger.py` | `AsyncAuditLogger` — non-blocking enqueue, background worker, batched writes, health signal. |
| `app/audit/schema.sql` | PostgreSQL append-only DDL (production target). |
| `app/audit/schema_sqlite.sql` | SQLite append-only DDL (Day 1-2 fallback). |
| `scripts/init_audit_db.py` | Creates the DB and applies the schema (`--backend sqlite\|pg`). |
| `scripts/audit_demo.py` | End-to-end demo: writes 4 sample decisions, runs the 3 review queries, proves append-only. |
| `tests/audit/test_models.py` | 16 model/hash/validation/serialization tests. |
| `tests/audit/test_logger.py` | 6 end-to-end logger + storage tests. |
| `requirements-audit.txt` | `asyncpg` (prod only) + `pytest`. |
| `docs/audit_log.md` | How-to / integration guide for the team. |

### The locked AuditRecord schema

`request_id` · `timestamp` (ISO-8601 UTC) · `user_id` · `role` · `service` ·
`prompt_hash` (SHA-256) · `policy_triggered` · `decision` · `reason` ·
`actor_type` · `rule_triggered` · `latency_ms` · `signals` · `policy_version`.

These match the field list locked in both the sprint plan and the Master
Analysis (Part 4, action 6).

## 3. Key design decisions (and why)

**a) Two backends behind one interface — PostgreSQL + a SQLite fallback.**
The unified architecture (`Sentinel_Master_Analysis_Deveshi.pdf`, gap **R-G4**)
mandates **PostgreSQL** for the 7-year compliance trail, replacing Ryan's SQLite.
But this machine has no PostgreSQL and no `asyncpg`. Rather than ship code that
can't run, I implemented the documented **risk mitigation** verbatim: SQLite for
Day 1-2, swap the driver later. The `AuditRecord` model and `AsyncAuditLogger`
API are identical for both backends, so Day-3 cutover is a one-line change.

**b) Raw prompts are structurally impossible to store.**
The policy document (P-01, P-06; the AuditRecord spec) says store
`prompt_hash`, never the raw prompt. There is **no** `prompt` field on the
record — the only way text enters is via `hash_prompt()` (SHA-256). A test dumps
the entire DB file and asserts the secret string is absent and the hash present.

**c) Append-only / tamper-evidence is enforced in the database.**
Not in application code (which can be bypassed). SQLite uses `BEFORE UPDATE/DELETE`
triggers that `RAISE(ABORT)`; PostgreSQL adds a raising trigger **and** grants the
app role `INSERT, SELECT` only. This satisfies the "immutable, tamper-evident"
integration requirement.

**d) Decoupled from teammates' unfinished code.**
On Day 1, Samarth's `decision.py` and Ryan's `RequestContext` don't exist yet, so
I don't import them. `decision`/`actor_type` are plain strings, and
`AuditRecord.from_decision()` reads teammate objects by **duck typing** (guarded
by `TYPE_CHECKING`). I can build and test the whole subsystem without being
blocked — and it slots into their objects the moment they land.

**e) The request path never waits on the DB.**
`AsyncAuditLogger.log()` just enqueues; a single background worker batches and
writes. A `healthy` flag flips on backend failure so Day-3's PEP can fail closed
("DB down → ESCALATE rather than answer un-audited").

## 4. How to run / verify

```bash
# 1. Create the local audit DB (append-only schema):
python scripts/init_audit_db.py --backend sqlite --path ./sentinel_audit.db

# 2. Run the test suite:
python -m pytest tests/audit -q

# 3. End-to-end demo (proves the Day-1 gate):
python scripts/audit_demo.py
```

### Verified results on this machine

- **`pytest tests/audit -q` → `22 passed`** (no external services, no
  pytest-asyncio needed — async tests are driven via `asyncio.run`).
- **`audit_demo.py`** writes one record per decision type, then prints:
  - Query 1 — all decisions this session (4 rows)
  - Query 2 — all STOP decisions (2 rows)
  - Query 3 — all ESCALATE decisions (1 row)
  - Append-only check → `[OK] UPDATE blocked: audit_log is append-only`

The demo's sample decisions map to real rules from the policy doc: a safe
question (ALLOW), customer PII (R-01 STOP), a DB credential (R-07 STOP), and bulk
export (R-05 ESCALATE).

## 5. Day-1 gate — status

✅ **Met.** A simulated request flow produces a `Decision`-shaped outcome → an
`AuditRecord` (raw prompt hashed) → enqueued → persisted to the append-only
table → read back by the review queries. Full plumbing, no detection logic, as
the gate specifies.

## 6. What's next / out of scope

| Item | When | Owner |
|---|---|---|
| Real secrets/credential scanner (R-07): regex + bloom filter (AKIA, postgres URIs, PEM, Bearer, `.env`, entropy) | **Day 2** | Nikhil (me) |
| Finalize logger against **real PostgreSQL** (swap backend, run `init` with `--backend pg`) | **Day 3** | Nikhil |
| Demo SQL queries + screenshot of the 7-year compliance record | **Day 3-4** | Nikhil |
| SHA-256 **hash chain** on the log (`prev_hash`/`record_hash` columns already reserved in the schema) | **V2** | — |
| Real EIM identity, HA Postgres | **V2** | — |

I did **not** touch files owned by teammates: `pyproject.toml`/`README.md`
(Adhiraj), `decision.py`/`pipeline.py` (Samarth), `detectors/*` (Sneha's stubs),
or the FastAPI PEP (Ryan).
