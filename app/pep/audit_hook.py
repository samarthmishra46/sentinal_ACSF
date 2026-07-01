# RYAN-DAY3
"""Audit call-site adapter — the PEP's hook into the append-only audit log.

Owner: Ryan (the PEP *calls* the logger; Nikhil owns app/audit/* — models,
AsyncAuditLogger, backends). Day-3: ``app/audit/*`` is on devlop, so the
documented swap is DONE:

  * ``AuditSink`` — the structural interface the PEP depends on.
  * ``LoggerAuditSink`` — the live sink: builds ``AuditRecord.from_decision``,
    resolves ``policy_triggered`` via the shared catalog, and enqueues on
    Nikhil's ``AsyncAuditLogger``. ``/v1/chat`` is a *sync* route (Starlette
    threadpool), and ``asyncio.Queue`` is not thread-safe, so the enqueue hops
    to the event-loop thread with ``loop.call_soon_threadsafe`` — this resolves
    the caveat Nikhil flagged in his Day-2 notes without touching his module.
  * ``ConsoleAuditSink`` — fallback when the logger has not been started (unit
    tests / TestClient without lifespan): same fields, one JSON line to stdout.
  * ``default_sink()`` — returns the singleton ``LoggerAuditSink``; ``startup()``
    / ``shutdown()`` are called by the FastAPI lifespan to run the worker.

Fail-closed (Day-3): ``is_healthy()`` exposes the logger's backend health so
ingress can ESCALATE instead of answering un-audited when the DB is down.

Privacy invariant (from the policy doc & Nikhil's models): raw prompts are NEVER
stored. The only path in is a SHA-256 digest, so this sink hashes locally too.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol

from app._compat import Decision, RequestContext
from app.audit import AsyncAuditLogger, AuditRecord, SqliteBackend
from app.config import settings
from app.policy.models import Snapshot, policy_for

# Map the PEP's user-facing decision strings onto Nikhil's controlled vocabulary
# (DECISIONS frozenset). Identity today; the indirection documents the contract.
_DECISION_VOCAB = {"ALLOW": "ALLOW", "STOP": "STOP", "ESCALATE": "ESCALATE", "REDACT": "REDACT"}


def hash_prompt(prompt: str) -> str:
    """SHA-256 hex digest — the only sanctioned way a prompt enters a record."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _resolve_policy_id(snapshot: Optional[Snapshot], rule_id: Optional[str]) -> Optional[str]:
    """Resolve ``policy_triggered`` from the rule via the SHARED catalog lookup.

    ``policy_for(snapshot, rule_id)`` is the single source of truth (Sneha's
    catalog.yaml, rule_id -> {policy_id, ...}), so the PEP and Nikhil's audit read
    the same value. Returns the catalog entry's ``policy_id``, or ``None`` when
    there is no snapshot / rule / catalog match (fail-safe, never invents a value).
    """
    if snapshot is None or not rule_id:
        return None
    meta = policy_for(snapshot, rule_id)
    if isinstance(meta, dict):
        return meta.get("policy_id")
    if isinstance(meta, str):
        return meta
    return None


class AuditSink(Protocol):
    """Structural interface the PEP depends on for audit. Any object with this
    ``record`` shape satisfies it (the console stub today, Nikhil's logger later).
    """

    def record(
        self,
        decision: Decision,
        response: dict,
        *,
        prompt: str,
        ctx: Optional[RequestContext],
        latency_ms: float,
        snapshot: Optional[Snapshot] = None,
    ) -> None:
        ...


class ConsoleAuditSink:
    """V1 audit sink: one JSON line per request, fields == Nikhil's AuditRecord."""

    def record(
        self,
        decision: Decision,
        response: dict,
        *,
        prompt: str,
        ctx: Optional[RequestContext],
        latency_ms: float,
        snapshot: Optional[Snapshot] = None,
    ) -> None:
        sig = decision.decisive_signal
        rule_id = sig.rule_id if sig else None
        record = {
            "request_id": str(uuid.uuid4()),
            "ts": datetime.now(timezone.utc).isoformat(),
            "user_id": ctx.user_id if ctx else None,
            "role": ctx.role if ctx else None,
            "service": ctx.owned_services[0] if ctx and ctx.owned_services else None,
            "prompt_hash": hash_prompt(prompt),
            # Resolved here from the shared catalog (was always None before) so the
            # audit log actually cites the policy, not a blank.
            "policy_triggered": _resolve_policy_id(snapshot, rule_id),
            "decision": _DECISION_VOCAB.get(response.get("decision", ""), response.get("decision")),
            "reason": decision.reason,
            # Anamika's EIM now classifies the actor (PR #13); fall back to A-01
            # (human) if the field is absent on an older RequestContext.
            "actor_type": getattr(ctx, "actor_type", "A-01") if ctx else "A-01",
            "rule_triggered": rule_id,
            "latency_ms": round(latency_ms, 2),
            "signals": [s.detector for s in decision.signals],
            "policy_version": decision.policy_version,
        }
        print(f"[AUDIT] {json.dumps(record)}")


class LoggerAuditSink:
    """Adapts Nikhil's ``AsyncAuditLogger`` to the ``AuditSink`` protocol.

    Until ``start()`` runs (inside the FastAPI lifespan, on the event loop) the
    sink degrades to the console fallback, so importing the app or driving it
    with a bare TestClient never requires a running loop or a database.
    """

    def __init__(self, logger: AsyncAuditLogger) -> None:
        self._logger = logger
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._fallback = ConsoleAuditSink()

    # --- lifecycle (called from app.main's lifespan) ------------------------- #

    async def start(self) -> None:
        await self._logger.start()
        self._loop = asyncio.get_running_loop()

    async def stop(self) -> None:
        self._loop = None
        await self._logger.stop(drain=True)

    @property
    def healthy(self) -> bool:
        """False once the backend errored — ingress fails closed on this."""
        return self._logger.healthy

    # --- AuditSink ------------------------------------------------------------ #

    def record(
        self,
        decision: Decision,
        response: dict,
        *,
        prompt: str,
        ctx: Optional[RequestContext],
        latency_ms: float,
        snapshot: Optional[Snapshot] = None,
    ) -> None:
        if self._loop is None:
            self._fallback.record(
                decision, response, prompt=prompt, ctx=ctx,
                latency_ms=latency_ms, snapshot=snapshot,
            )
            return
        try:
            rec = AuditRecord.from_decision(
                decision, ctx, prompt=prompt, latency_ms=round(latency_ms, 2)
            )
            # from_decision cites the rule; policy_triggered is the PEP's to
            # resolve — same shared catalog lookup the console sink uses.
            rec.policy_triggered = _resolve_policy_id(snapshot, rec.rule_triggered) or ""
            # Sync route -> threadpool thread; asyncio.Queue is not thread-safe,
            # so hand the enqueue to the loop thread (Nikhil's log_nowait caveat).
            self._loop.call_soon_threadsafe(self._logger.log_nowait, rec)
        except Exception as exc:  # audit must never 500 the request path
            print(
                f"[sentinel.audit] record build/enqueue failed "
                f"({type(exc).__name__}: {exc}); falling back to console",
                file=sys.stderr,
            )
            self._fallback.record(
                decision, response, prompt=prompt, ctx=ctx,
                latency_ms=latency_ms, snapshot=snapshot,
            )


# --- module singleton + lifespan hooks ---------------------------------------- #

_sink: Optional[LoggerAuditSink] = None


def _sqlite_path() -> Path:
    """Audit DB path from Adhiraj's ``settings.DB_URL`` (sqlite:/// URL or path)."""
    url = settings.DB_URL
    if url.startswith("sqlite:///"):
        return Path(url[len("sqlite:///"):])
    # Non-sqlite URL (e.g. postgres) is a V2/ops concern — Nikhil's documented
    # Day 1-2 fallback is the SQLite backend, same interface.
    return Path(__file__).resolve().parents[2] / "audit.db"


def default_sink() -> AuditSink:
    """Return the active audit sink — Nikhil's async logger behind the adapter."""
    global _sink
    if _sink is None:
        _sink = LoggerAuditSink(AsyncAuditLogger(SqliteBackend(_sqlite_path())))
    return _sink


def is_healthy() -> bool:
    """Audit-path health for ingress' fail-closed gate (unstarted == healthy)."""
    return _sink.healthy if _sink is not None else True


async def startup() -> None:
    """Connect the backend and spawn the writer (call from the app lifespan)."""
    sink = default_sink()
    if isinstance(sink, LoggerAuditSink):
        await sink.start()


async def shutdown() -> None:
    """Drain the queue and close the backend (call from the app lifespan)."""
    if _sink is not None:
        await _sink.stop()
