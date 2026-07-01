"""Immutable policy snapshot model.

Leaf module: imports nothing internal. The snapshot is the hot-swappable unit
the ``PolicyStore`` hands out to the pipeline on every evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Mapping

# The version stamped on the compiled bundle. Hardcoded for V1; Day-3 hot-reload
# will derive this from bundle content so a change bumps the version automatically.
BUNDLE_VERSION = "v1.0"


@dataclass(frozen=True)
class Snapshot:
    """An immutable, hot-swappable bundle of compiled policy.

    Immutability is what makes atomic hot-reload safe: a reader either sees the
    whole old snapshot or the whole new one, never a half-applied mix.
    """

    version: str
    created_at: datetime
    catalog: Mapping[str, Any] = field(default_factory=dict)  # rule id -> metadata
    cedar_text: str = ""  # raw Cedar source (Anamika's cedar_engine evaluates it)

    @classmethod
    def empty(cls) -> "Snapshot":
        """Return a versioned empty snapshot (safe default before any reload)."""
        return cls(version="empty", created_at=datetime.now(timezone.utc))

    @classmethod
    def from_bundle(cls, bundle_path: str | Path) -> "Snapshot":
        """Compile a snapshot from a policy bundle directory (e.g. policies/v1).

        Reads ``catalog.yaml`` into ``catalog`` (keyed by rule id) and
        ``authz.cedar`` into ``cedar_text``. Raises if the bundle is malformed —
        callers that need a safe default should catch and fall back to
        ``Snapshot.empty()``.
        """
        import yaml  # lazy: keeps this leaf module importable without PyYAML

        bundle = Path(bundle_path)
        raw = yaml.safe_load((bundle / "catalog.yaml").read_text(encoding="utf-8")) or {}
        policies = raw.get("policies", []) if isinstance(raw, dict) else []
        catalog = {p["id"]: p for p in policies if isinstance(p, dict) and "id" in p}

        cedar_file = bundle / "authz.cedar"
        cedar_text = cedar_file.read_text(encoding="utf-8") if cedar_file.exists() else ""

        return cls(
            version=BUNDLE_VERSION,
            created_at=datetime.now(timezone.utc),
            catalog=catalog,
            cedar_text=cedar_text,
        )


def policy_for(snapshot: Snapshot, rule_id: str | None) -> Any | None:
    """Look up a rule's policy metadata in the snapshot catalog.

    The single shared lookup so the PEP and the audit logger resolve
    ``policy_triggered`` from a ``rule_id`` identically. None-safe: returns
    ``None`` for a missing rule or a ``None`` rule_id (e.g. infra signals).
    """
    if rule_id is None:
        return None
    return snapshot.catalog.get(rule_id)
