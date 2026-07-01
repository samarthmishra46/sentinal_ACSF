"""Asynchronous, non-blocking audit logger.

The request path must never wait on a database write. Callers ``await log(record)``
(or ``log_nowait(record)``), which just enqueues onto an ``asyncio.Queue``; a
single background worker drains the queue and writes to the backend in batches.

Health signal: if the backend starts failing, :attr:`healthy` flips to ``False``.
On Day 3, the PEP uses this to fail closed — "if the DB is down, ESCALATE rather
than answer un-audited" — instead of silently dropping the compliance record.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Optional

from .backends import AuditBackend
from .models import AuditRecord

log = logging.getLogger("sentinel.audit")

# Sentinel object that tells the worker to drain and exit.
_STOP = object()


class AsyncAuditLogger:
    def __init__(
        self,
        backend: AuditBackend,
        *,
        maxsize: int = 10_000,
        batch_size: int = 50,
    ) -> None:
        self.backend = backend
        self.maxsize = maxsize
        self.batch_size = batch_size
        self._queue: Optional[asyncio.Queue] = None
        self._worker: Optional[asyncio.Task] = None
        self._healthy = True
        self._written = 0
        self._dropped = 0

    # --- properties ----------------------------------------------------------

    @property
    def healthy(self) -> bool:
        """False once the backend has errored; consumers can fail closed on this."""
        return self._healthy

    @property
    def written(self) -> int:
        """Records successfully persisted since start()."""
        return self._written

    @property
    def dropped(self) -> int:
        """Records dropped because the queue was full (log_nowait backpressure)."""
        return self._dropped

    # --- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Connect the backend and spawn the background writer."""
        if self._worker is not None:
            return
        self._queue = asyncio.Queue(maxsize=self.maxsize)
        await self.backend.connect()
        self._worker = asyncio.create_task(self._run(), name="audit-writer")

    async def stop(self, *, drain: bool = True) -> None:
        """Stop the worker. If ``drain``, flush all queued records first."""
        if self._worker is None:
            return
        assert self._queue is not None
        if drain:
            await self._queue.put(_STOP)
        else:
            # Best-effort: clear the queue, then signal stop.
            while not self._queue.empty():
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except asyncio.QueueEmpty:
                    break
            await self._queue.put(_STOP)
        await self._worker
        self._worker = None
        await self.backend.close()

    # --- enqueue -------------------------------------------------------------

    async def log(self, record: AuditRecord) -> None:
        """Enqueue a record, awaiting if the queue is full (back-pressure)."""
        assert self._queue is not None, "call start() first"
        await self._queue.put(record)

    def log_nowait(self, record: AuditRecord) -> bool:
        """Enqueue without awaiting. Returns False if the queue was full.

        Use on the hot path when you would rather drop-and-count than block. The
        caller can react to a False by failing closed.
        """
        assert self._queue is not None, "call start() first"
        try:
            self._queue.put_nowait(record)
            return True
        except asyncio.QueueFull:
            self._dropped += 1
            log.error("audit queue full; dropped record %s", record.request_id)
            return False

    # --- worker --------------------------------------------------------------

    async def _run(self) -> None:
        assert self._queue is not None
        while True:
            batch = await self._collect_batch()
            stop = False
            if batch and batch[-1] is _STOP:
                stop = True
                batch = batch[:-1]
            if batch:
                await self._flush(batch)
            for _ in range(len(batch) + (1 if stop else 0)):
                self._queue.task_done()
            if stop:
                return

    async def _collect_batch(self) -> list:
        """Block for one item, then greedily pull up to batch_size more."""
        assert self._queue is not None
        first = await self._queue.get()
        batch = [first]
        if first is _STOP:
            return batch
        while len(batch) < self.batch_size and not self._queue.empty():
            item = self._queue.get_nowait()
            batch.append(item)
            if item is _STOP:
                break
        return batch

    async def _flush(self, records: list[AuditRecord]) -> None:
        try:
            await self.backend.write_many(records)
            self._written += len(records)
            if not self._healthy:
                self._healthy = True
                log.warning("audit backend recovered")
        except Exception:  # noqa: BLE001 - never let the worker die
            self._healthy = False
            # Audit failures must be loud; this is a compliance control.
            log.exception(
                "audit backend write failed for %d record(s)", len(records)
            )
            print(
                f"[sentinel.audit] CRITICAL: failed to persist {len(records)} "
                f"audit record(s); backend marked unhealthy",
                file=sys.stderr,
            )
