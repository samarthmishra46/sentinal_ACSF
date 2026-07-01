# Integration Contract — Nikhil's Audit Subsystem ↔ the rest of Sentinel

This is what my audit code (`app/audit/`) **needs from** teammates and **provides
to** them. Hand the relevant row to each person.

> **Important:** my Day-1 code runs and all 22 tests pass **standalone today** —
> it imports nothing from teammates. You can paste their (even half-finished)
> files into the repo and my tests stay green, because I only import `app.audit`.
> The items below are for *full-system* integration, not to make my part run.

---

## TIER 1 — What my code actually reads (only 2 objects)

My helper `AuditRecord.from_decision(decision, context, prompt=...)` reads
attributes off two teammate objects by **duck typing** (it tries several names and
degrades gracefully). To get *accurate* audit fields, the objects should expose:

### From Samarth — `app/pdp/decision.py` → `Decision`
| I read | Accepted attribute names | Notes |
|---|---|---|
| decision/outcome | `.disposition` **or** `.decision` **or** `.outcome` | enum with `.name`, or str, or number (`0=ALLOW, 1=ESCALATE, 1.5=REDACT, 2=STOP`). Missing → fails closed to `ESCALATE`. |
| reason | `.reason` **or** `.message` | human-readable string |
| rule | `.rule_triggered` **or** `.rule` | e.g. `"R-01"` |
| policy | `.policy_triggered` **or** `.policy` | e.g. `"P-01"` |
| signals | `.signals` | list of `str`, or objects with `.label`/`.name`/`.id`/`.rule` |
| prompt hash | `.prompt_hash` *(optional)* | if absent, I hash the `prompt=` you pass instead |
| latency | `.latency_ms` *(optional)* | else taken from the `latency_ms=` kwarg |

### From Anamika/Ryan — `app/identity/context.py` → `RequestContext`
| I read | Accepted attribute names | Notes |
|---|---|---|
| user | `.user_id` **or** `.user` | from EIM |
| role | `.role` | `Engineer`/`Support`/`SecurityReviewer`/`ComplianceOfficer` |
| service | `.service` **or** `.owned_service` | queried service |
| actor type | `.actor_type` **or** `.actor` | `A-01`…`A-04` |

If any name differs from the above, either rename on their side or tell me and I
add the alias in `models.py::_first_attr` (one-line change).

---

## TIER 2 — Who calls my code, and how (Ryan owns this)

Ryan's PEP (`app/pep/`) is the only place that drives the logger. The contract:

```python
from app.audit import AsyncAuditLogger, AuditRecord, SqliteBackend  # PostgresBackend later

# --- at app startup (once) ---
audit = AsyncAuditLogger(SqliteBackend(settings.AUDIT_DB_PATH))
await audit.start()

# --- per request, AFTER the pipeline returns a Decision ---
record = AuditRecord.from_decision(decision, ctx, prompt=raw_prompt,
                                   latency_ms=elapsed_ms)
await audit.log(record)            # non-blocking; never awaits the DB write

# Fail closed if the audit store is down (compliance requirement):
if not audit.healthy:
    return escalate("audit log unavailable")   # don't answer un-audited

# --- at app shutdown (once) ---
await audit.stop(drain=True)       # flushes the queue
```

Everyone imports from `app.audit` only — never from the submodules.

---

## TIER 3 — Full file list, so we can assemble one repo

Each person owns these paths (from the sprint plan). Drop the files in at these
locations and the package lays out cleanly:

| Person | Files they own |
|---|---|
| **Samarth** | `app/pdp/decision.py`, `app/pdp/pipeline.py`, `app/pdp/combiner.py`, `app/policy/store.py`, `app/policy/models.py`, `tests/redteam/` |
| **Ryan** | `app/pep/main.py`, `app/pep/enforcement.py`, `app/pdp/output_scanner.py`, `app/assistant/stub.py`, `app/escalation/queue.py` |
| **Anamika** | `app/identity/context.py`, `app/identity/eim_client.py`, `app/pdp/authz/cedar_engine.py`, `app/pdp/authz/rbac.py`, `app/pdp/authz/scope.py` |
| **Sneha** | `app/pdp/detectors/base.py`, `app/pdp/detectors/{pii,injection,intent}.py`, `policies/v1/{authz.cedar,catalog.yaml}`, `tests/redteam/prompts.yaml` |
| **Nikhil (me)** | `app/audit/*`, `app/pdp/detectors/secrets.py` *(Day 2)*, `scripts/init_audit_db.py`, `tests/audit/*` ✅ done |
| **Adhiraj** | `pyproject.toml`, `README.md`, `app/config.py`, `app/monitoring/{signals,ratelimit}.py` |

### The two things I most need from the team to integrate
1. **Samarth's `app/pdp/decision.py`** — so `from_decision` maps to the real enum.
2. **The `RequestContext`** (Anamika/Ryan) — so user/role/actor land in each record.

Everything else is independent of my code.

### Config I'd like from Adhiraj (`app/config.py`)
`AUDIT_DB_PATH` (sqlite) and/or `AUDIT_PG_DSN` (postgres), plus `POLICY_VERSION`.
Until that exists I use safe defaults (`sentinel_audit.db`, `"v1.0"`).
