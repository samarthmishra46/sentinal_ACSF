"""Policy store: holds the active snapshot and swaps it atomically.

Imports only ``policy.models`` (a leaf), keeping the DAG clean.
"""

from __future__ import annotations

import threading

from app.policy.models import Snapshot


class PolicyStore:
    """Holds the currently active policy ``Snapshot`` behind an atomic swap."""

    def __init__(self, initial: Snapshot | None = None) -> None:
        """Start with ``initial`` or an empty snapshot."""
        self._lock = threading.Lock()
        self._active: Snapshot = initial if initial is not None else Snapshot.empty()

    @property
    def active(self) -> Snapshot:
        """Return the current snapshot (a plain atomic reference read)."""
        return self._active

    def reload(self, new: Snapshot) -> None:
        """Atomically swap the active snapshot under a lock.

        STUB: the real version will compile a Snapshot from disk; today it just
        swaps in the one provided. The lock serialises concurrent reloads;
        readers of ``active`` see only fully-formed snapshots.
        """
        with self._lock:
            self._active = new
