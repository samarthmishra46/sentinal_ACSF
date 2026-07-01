"""Monitoring signals for threat, role, and decision counters."""

from __future__ import annotations

from collections import defaultdict
from threading import Lock
from typing import DefaultDict

_counters: DefaultDict[str, DefaultDict[str, int]] = defaultdict(lambda: defaultdict(int))
_lock = Lock()


def increment(threat_type: str, role: str, decision: str) -> None:
    """Increment the counter for a given threat type, role, and decision."""
    key = f"{threat_type}:{role}:{decision}"
    with _lock:
        _counters[key]["count"] += 1


def get_counts() -> dict[str, dict[str, int]]:
    """Return a snapshot of current counter values."""
    with _lock:
        return {k: dict(v) for k, v in _counters.items()}
