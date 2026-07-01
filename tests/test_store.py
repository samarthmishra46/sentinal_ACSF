"""Contract tests for the policy store (auto-load + atomic reload)."""

from __future__ import annotations

from app.policy.models import Snapshot
from app.policy.store import PolicyStore


def test_auto_loads_bundle_on_startup() -> None:
    store = PolicyStore()  # no args -> compiles policies/v1 from disk
    assert store.active.version == "v1.0"
    assert "R-01" in store.active.catalog


def test_missing_bundle_falls_back_to_empty() -> None:
    store = PolicyStore(bundle_path="/nonexistent/bundle")
    assert store.active.version == "empty"  # never crashes the PEP


def test_explicit_initial_snapshot_wins() -> None:
    snap = Snapshot.empty()
    assert PolicyStore(initial=snap).active is snap


def test_reload_swaps_atomically() -> None:
    store = PolicyStore()
    store.reload(Snapshot.empty())
    assert store.active.version == "empty"


def test_reload_from_disk_recompiles() -> None:
    store = PolicyStore(initial=Snapshot.empty())
    assert store.reload_from_disk() is True
    assert store.active.version == "v1.0"


def test_reload_from_disk_keeps_current_on_failure() -> None:
    store = PolicyStore()  # good snapshot
    assert store.reload_from_disk("/nonexistent/bundle") is False
    assert store.active.version == "v1.0"  # unchanged
