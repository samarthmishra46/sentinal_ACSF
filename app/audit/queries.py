"""Read-side helpers for the audit log — the demo / review queries (Day 3-4).

These answer the questions the sprint plan lists for Nikhil's Day 3:

  * all STOP decisions in the last hour
  * all escalations
  * latency distribution (avg / p50 / p95 / p99)
  * decision counts

They are backend-agnostic: everything goes through ``AuditBackend.fetch(...)``
with structured filters, so the same call works on SQLite (Day 1-2) and
PostgreSQL (production) unchanged. Timestamps are ISO-8601 UTC, so a string
``ts >= since`` comparison is chronological.

Usage::

    from app.audit import SqliteBackend, queries
    backend = SqliteBackend("sentinel_audit.db"); await backend.connect()
    stops = await queries.stops_last_hour(backend)
    stats = await queries.latency_stats(backend)
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any

from .backends import AuditBackend
from .models import AuditRecord


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def hours_ago_iso(hours: float) -> str:
    """ISO-8601 UTC timestamp ``hours`` in the past (for ``since_ts`` filters)."""
    return (utc_now() - timedelta(hours=hours)).isoformat()


async def by_decision(backend: AuditBackend, decision: str) -> list[AuditRecord]:
    """All records with a given decision (ALLOW/STOP/ESCALATE/REDACT/…)."""
    return await backend.fetch(decision=decision)


async def stops_last_hour(backend: AuditBackend) -> list[AuditRecord]:
    """All STOP decisions in the last hour (demo query #1)."""
    return await backend.fetch(decision="STOP", since_ts=hours_ago_iso(1))


async def escalations(backend: AuditBackend) -> list[AuditRecord]:
    """All ESCALATE decisions awaiting / sent to human review (demo query #2)."""
    return await backend.fetch(decision="ESCALATE")


async def for_user(backend: AuditBackend, user_id: str) -> list[AuditRecord]:
    """Full audit trail for one user (session review)."""
    return await backend.fetch(user_id=user_id)


async def decision_counts(backend: AuditBackend) -> dict[str, int]:
    """Count of records per decision type."""
    counts: dict[str, int] = {}
    for rec in await backend.fetch():
        counts[rec.decision] = counts.get(rec.decision, 0) + 1
    return counts


async def latency_stats(
    backend: AuditBackend,
    *,
    decision: str | None = None,
    since_ts: str | None = None,
) -> dict[str, Any]:
    """Latency distribution over matching records (demo query #3).

    Returns ``count`` plus, when non-empty, ``min_ms/avg_ms/p50_ms/p95_ms/
    p99_ms/max_ms``. Percentiles use the nearest-rank method. Computed in Python
    so it is identical on SQLite and PostgreSQL (fine for demo-scale volumes;
    push to SQL aggregates if this ever runs over the full 7-year table).
    """
    records = await backend.fetch(decision=decision, since_ts=since_ts)
    values = sorted(r.latency_ms for r in records)
    if not values:
        return {"count": 0}
    return {
        "count": len(values),
        "min_ms": values[0],
        "avg_ms": round(sum(values) / len(values), 3),
        "p50_ms": _percentile(values, 50),
        "p95_ms": _percentile(values, 95),
        "p99_ms": _percentile(values, 99),
        "max_ms": values[-1],
    }


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Nearest-rank percentile of an already-sorted list."""
    if not sorted_values:
        return 0.0
    rank = math.ceil((pct / 100.0) * len(sorted_values))
    idx = min(max(rank, 1), len(sorted_values)) - 1
    return sorted_values[idx]
