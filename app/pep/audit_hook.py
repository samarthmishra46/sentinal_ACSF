# RYAN-DAY2
"""Audit call-site adapter — the PEP's hook into the append-only audit log.

Owner: Ryan (the PEP *calls* the logger; Nikhil owns app/audit/* — models,
AsyncAuditLogger, Postgres backend). Per the team contract I do not import his
modules until they merge to devlop; instead this defines the seam:

  * ``AuditSink`` — the structural interface the PEP depends on.
  * ``ConsoleAuditSink`` — V1 default: emits one line of JSON per request with
    EXACTLY Nikhil's locked AuditRecord field names, so the shape is wire-ready.
  * ``default_sink()`` — the single swap point. On integration this returns an
    adapter that builds ``AuditRecord.from_decision(...)`` and calls
    ``AsyncAuditLogger.log_nowait(record)`` (sync, non-blocking — keeps the route
    sync). Until then it returns the console sink.

Privacy invariant (from the policy doc & Nikhil's models): raw prompts are NEVER
stored. The only path in is a SHA-256 digest, so this sink hashes locally too.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Protocol

from app._compat import Decision, RequestContext

# Map the PEP's user-facing decision strings onto Nikhil's controlled vocabulary
# (DECISIONS frozenset). Identity today; the indirection documents the contract.
_DECISION_VOCAB = {"ALLOW": "ALLOW", "STOP": "STOP", "ESCALATE": "ESCALATE", "REDACT": "REDACT"}


def hash_prompt(prompt: str) -> str:
    """SHA-256 hex digest — the only sanctioned way a prompt enters a record."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


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
    ) -> None:
        sig = decision.decisive_signal
        record = {
            "request_id": str(uuid.uuid4()),
            "ts": datetime.now(timezone.utc).isoformat(),
            "user_id": ctx.user_id if ctx else None,
            "role": ctx.role if ctx else None,
            "service": ctx.owned_services[0] if ctx and ctx.owned_services else None,
            "prompt_hash": hash_prompt(prompt),
            "policy_triggered": None,  # audit logger resolves rule_id -> policy via snapshot
            "decision": _DECISION_VOCAB.get(response.get("decision", ""), response.get("decision")),
            "reason": decision.reason,
            "actor_type": "A-01",      # TODO: from EIM actor classification (Anamika)
            "rule_triggered": sig.rule_id if sig else None,
            "latency_ms": round(latency_ms, 2),
            "signals": [s.detector for s in decision.signals],
            "policy_version": decision.policy_version,
        }
        print(f"[AUDIT] {json.dumps(record)}")


def default_sink() -> AuditSink:
    """Return the active audit sink (the swap point for Nikhil's logger).

    V1: console. On integration, replace the body with an adapter that wraps
    ``app.audit.logger.AsyncAuditLogger`` and calls ``log_nowait`` per request.
    """
    return ConsoleAuditSink()
