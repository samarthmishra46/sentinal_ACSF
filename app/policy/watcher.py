"""Hot-reload watcher: recompile the policy bundle when its files change.

Dependency-free by design — a lightweight background thread polls the bundle
files' modification times (no ``watchdog``/inotify dependency, which keeps the
install slim and portable). On a change it calls ``store.reload_from_disk()``,
which atomically swaps in the new snapshot; readers never see a half-applied
policy, and a malformed bundle leaves the old snapshot in place.

Imports only ``policy.store`` — keeps the dependency DAG clean.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from app.policy.store import PolicyStore

logger = logging.getLogger(__name__)

# The bundle files whose mtimes we track.
_WATCHED_FILES = ("catalog.yaml", "authz.cedar")


class PolicyWatcher:
    """Polls a policy bundle and hot-reloads the store when it changes."""

    def __init__(
        self,
        store: PolicyStore,
        bundle_path: str | Path | None = None,
        interval: float = 1.0,
    ) -> None:
        """Watch ``bundle_path`` (defaults to the store's bundle) every ``interval`` seconds."""
        self._store = store
        self._bundle_path = Path(bundle_path) if bundle_path else store.bundle_path
        self._interval = interval
        self._signature = self._current_signature()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def _current_signature(self) -> tuple:
        """A tuple of (name, mtime) for each watched file that exists."""
        sig = []
        for name in _WATCHED_FILES:
            f = self._bundle_path / name
            if f.exists():
                sig.append((name, f.stat().st_mtime_ns))
        return tuple(sig)

    def poll_once(self) -> bool:
        """Check for a change; reload the store if the bundle changed.

        Returns True if a reload happened. Synchronous and side-effect-safe —
        this is the unit the background loop calls, and what tests drive directly.
        """
        current = self._current_signature()
        if current == self._signature:
            return False
        logger.info("policy bundle %s changed; hot-reloading", self._bundle_path)
        reloaded = self._store.reload_from_disk(self._bundle_path)
        # Advance the signature even if the reload failed, so we don't spin
        # retrying a broken bundle every tick; the next real change re-triggers.
        self._signature = current
        return reloaded

    def start(self) -> None:
        """Start the background polling thread (idempotent)."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="policy-watcher", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the background thread to stop and wait briefly for it."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval * 2)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.poll_once()
            except Exception:  # a watcher must never die on a transient error
                logger.exception("policy watcher poll failed; continuing")
