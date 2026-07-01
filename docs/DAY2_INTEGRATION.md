# Day-2 Integration — one-line changes I need from teammates

I built **only my files** (secrets detector + audit hardening). The two edits
below are in teammate-owned files, so I'm **proposing** them here rather than
editing — apply as-is when you're ready.

## 1. Samarth — register the secrets detector (`app/pdp/factory.py`)

`SecretsDetector` implements `BaseDetector` and its `.scan` matches your
`Detector` alias exactly. Add it to `default_stages()` (stage 4, so it runs
before injection/pii/intent):

```python
# app/pdp/factory.py
from app.pdp.detectors.secrets import SecretsDetector   # + at top

def default_stages() -> list[Stage]:
    return [
        detector_stage(SecretsDetector().scan),   # Stage 4 · R-07 credentials
        # ... pii (6), injection (5), intent (7) as they land, sorted by stage_order
    ]
```

No changes to `detector_stage` or `Pipeline` — the adapter already turns a
`Signal` into a `Decision(disposition, reason, (signal,))`.

## 2. Ryan — swap the audit sink to my logger (`app/pep/audit_hook.py`)

Your `default_sink()` is the documented swap point. Replace its body with an
adapter around `AsyncAuditLogger` (my package must be merged to devlop first):

```python
# app/pep/audit_hook.py
from app.audit import AsyncAuditLogger, AuditRecord, SqliteBackend

class LoggerAuditSink:
    """Adapts Nikhil's AsyncAuditLogger to the AuditSink protocol."""
    def __init__(self, logger: AsyncAuditLogger) -> None:
        self._logger = logger

    def record(self, decision, response, *, prompt, ctx, latency_ms) -> None:
        rec = AuditRecord.from_decision(
            decision, ctx, prompt=prompt, latency_ms=latency_ms
        )
        self._logger.log_nowait(rec)   # non-blocking; drops+counts if saturated

_LOGGER: AsyncAuditLogger | None = None

def default_sink() -> "AuditSink":
    global _LOGGER
    if _LOGGER is None:
        _LOGGER = AsyncAuditLogger(SqliteBackend("sentinel_audit.db"))
    return LoggerAuditSink(_LOGGER)
```

Lifecycle (in your FastAPI startup/shutdown, e.g. a `lifespan`):

```python
await _LOGGER.start()          # startup: connect backend + spawn worker
...
await _LOGGER.stop(drain=True) # shutdown: flush the queue
```

**⚠ One caveat to confirm with me:** `log_nowait` uses `asyncio.Queue.put_nowait`,
which must be called from the event-loop thread. If your `/v1/chat` route is a
**sync** function (runs in Starlette's threadpool), tell me — I'll add a
thread-safe `submit()` (via `loop.call_soon_threadsafe`) to the logger so the
sink is safe from either context. If the route is `async def`, the code above is
fine as-is.

`from_decision` already reads your objects correctly (verified by tests):
`Decision.disposition` → decision string, `Decision.decisive_signal.rule_id` →
`rule_triggered`, `[s.detector]` → `signals`, `ctx.owned_services[0]` → `service`,
`Decision.policy_version` → `policy_version`.

## 3. Team — the devlop import break (not mine, but it blocks everyone)

`app/pdp/detectors/base.py` and `app/pdp/detectors/pii.py` do
`from app.identity.context import RequestContext` **at module top**, but
`app/identity/` isn't on devlop yet → importing any detector raises
`ModuleNotFoundError`. Two fixes (either works):

- **Anamika:** merge the identity package to devlop; or
- **Sneha:** move those two imports under `if TYPE_CHECKING:` (they're only type
  hints) — exactly what `pipeline.py` and my `secrets.py` already do.

My `secrets.py` deliberately keeps identity/Snapshot under `TYPE_CHECKING`, so it
does **not** add to this breakage.
