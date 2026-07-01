"""Policy store: holds the active snapshot and swaps it atomically.

Imports only ``policy.models`` (a leaf), keeping the DAG clean.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from app.policy.models import Snapshot

logger = logging.getLogger(__name__)

# Default policy bundle: <repo>/policies/v1. Hardcoded until Adhiraj's
# app/config.py exposes POLICY_BUNDLE_PATH (his PR #9 is still open/broken).
DEFAULT_BUNDLE_PATH = Path(__file__).resolve().parents[2] / "policies" / "v1"


class PolicyStore:
    """Holds the currently active policy ``Snapshot`` behind an atomic swap."""

    def __init__(
        self,
        initial: Snapshot | None = None,
        bundle_path: str | Path | None = None,
    ) -> None:
        """Start with ``initial``, else auto-compile the bundle from disk.

        Auto-loading means the live PEP screens with real policy (and the audit
        log gets real metadata) with no extra wiring. It is fail-safe: if the
        bundle is missing or malformed we fall back to an empty snapshot rather
        than crash the PEP at import time.
        """
        self._lock = threading.Lock()
        self._bundle_path = Path(bundle_path) if bundle_path else DEFAULT_BUNDLE_PATH
        if initial is not None:
            self._active: Snapshot = initial
        else:
            self._active = self._compile_or_empty(self._bundle_path)

    @staticmethod
    def _compile_or_empty(bundle_path: Path) -> Snapshot:
        """Compile a snapshot from disk, falling back to empty on any error."""
        try:
            return Snapshot.from_bundle(bundle_path)
        except Exception as exc:  # never let policy loading crash startup
            logger.warning("policy bundle %s failed to load: %r; using empty", bundle_path, exc)
            return Snapshot.empty()

    @property
    def active(self) -> Snapshot:
        """Return the current snapshot (a plain atomic reference read)."""
        return self._active

    def reload(self, new: Snapshot) -> None:
        """Atomically swap in a provided snapshot under a lock."""
        with self._lock:
            self._active = new

    def reload_from_disk(self, bundle_path: str | Path | None = None) -> bool:
        """Recompile from the bundle and atomically swap; keep the old on failure.

        Returns True if a new snapshot was swapped in. A failed reload leaves the
        currently-active snapshot untouched, so the PEP keeps serving good policy.
        (Day 3 will drive this from a file watcher for zero-downtime hot-reload.)
        """
        path = Path(bundle_path) if bundle_path else self._bundle_path
        try:
            new = Snapshot.from_bundle(path)
        except Exception as exc:
            logger.error("reload from %s failed: %r; keeping current snapshot", path, exc)
            return False
        with self._lock:
            self._active = new
        return True
