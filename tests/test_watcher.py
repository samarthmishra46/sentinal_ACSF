"""Tests for the policy hot-reload watcher."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from app.policy.store import PolicyStore
from app.policy.watcher import PolicyWatcher

REAL_BUNDLE = Path(__file__).resolve().parents[1] / "policies" / "v1"


def _temp_bundle(tmp_path: Path) -> Path:
    dest = tmp_path / "v1"
    shutil.copytree(REAL_BUNDLE, dest)
    return dest


def test_poll_no_change_returns_false(tmp_path: Path) -> None:
    bundle = _temp_bundle(tmp_path)
    store = PolicyStore(bundle_path=bundle)
    watcher = PolicyWatcher(store, bundle_path=bundle)
    assert watcher.poll_once() is False


def test_poll_reloads_on_change(tmp_path: Path) -> None:
    bundle = _temp_bundle(tmp_path)
    store = PolicyStore(bundle_path=bundle)
    assert "R-01" in store.active.catalog

    watcher = PolicyWatcher(store, bundle_path=bundle)

    # Rewrite the catalog with a distinct rule and force a newer mtime.
    catalog = bundle / "catalog.yaml"
    catalog.write_text('policies:\n  - id: "R-99"\n    disposition: STOP\n', encoding="utf-8")
    future = catalog.stat().st_mtime + 10
    os.utime(catalog, (future, future))

    assert watcher.poll_once() is True          # change detected -> reloaded
    assert "R-99" in store.active.catalog        # new policy is live
    assert "R-01" not in store.active.catalog    # old policy swapped out


def test_start_stop_is_clean(tmp_path: Path) -> None:
    bundle = _temp_bundle(tmp_path)
    store = PolicyStore(bundle_path=bundle)
    watcher = PolicyWatcher(store, bundle_path=bundle, interval=0.01)
    watcher.start()
    watcher.start()   # idempotent — second start is a no-op
    watcher.stop()    # must not raise
