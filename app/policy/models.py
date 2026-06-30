"""Immutable policy snapshot model.

Leaf module: imports nothing internal. The snapshot is the hot-swappable unit
the ``PolicyStore`` hands out to the pipeline on every evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from collections.abc import Mapping


@dataclass(frozen=True)
class Snapshot:
    """An immutable, hot-swappable bundle of compiled policy.

    Immutability is what makes atomic hot-reload safe: a reader either sees the
    whole old snapshot or the whole new one, never a half-applied mix.
    """

    version: str
    created_at: datetime
    catalog: Mapping[str, Any] = field(default_factory=dict)  # rule id -> metadata
    cedar_text: str = ""  # raw Cedar source, compiled later (V2)

    @classmethod
    def empty(cls) -> "Snapshot":
        """Return a versioned empty snapshot (safe default before any reload)."""
        return cls(version="empty", created_at=datetime.now(timezone.utc))


def policy_for(snapshot: Snapshot, rule_id: str | None) -> Any | None:
    """Look up a rule's policy metadata in the snapshot catalog.

    The single shared lookup so the PEP and the audit logger resolve
    ``policy_triggered`` from a ``rule_id`` identically. None-safe: returns
    ``None`` for a missing rule or a ``None`` rule_id (e.g. infra signals).
    """
    if rule_id is None:
        return None
    return snapshot.catalog.get(rule_id)
