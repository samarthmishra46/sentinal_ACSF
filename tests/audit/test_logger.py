"""End-to-end tests for AsyncAuditLogger + SqliteBackend.

These drive the async code with ``asyncio.run(...)`` from synchronous test
functions, so the suite needs no pytest-asyncio plugin (it isn't installed).
"""

from __future__ import annotations

import asyncio
import sqlite3
from typing import Sequence

import pytest

from app.audit import (
    AsyncAuditLogger,
    AuditBackend,
    AuditRecord,
    AuditUnavailable,
    SqliteBackend,
)
from app.audit.models import hash_prompt


def _record(decision: str, user: str = "u1", rule: str = "", prompt: str = "p") -> AuditRecord:
    return AuditRecord.new(
        user_id=user,
        role="Engineer",
        decision=decision,
        prompt=prompt,
        actor_type="A-01",
        rule_triggered=rule,
        latency_ms=1.0,
        signals=[f"sig:{decision}"],
    )


def _db_path(tmp_path) -> str:
    return str(tmp_path / "audit.db")


# --- happy path: write N, read N --------------------------------------------

def test_log_persists_all_records(tmp_path):
    path = _db_path(tmp_path)

    async def run():
        backend = SqliteBackend(path)
        logger = AsyncAuditLogger(backend)
        await logger.start()
        for i in range(25):
            await logger.log(_record("ALLOW", user=f"u{i}"))
        await logger.stop(drain=True)
        return logger.written

    written = asyncio.run(run())
    assert written == 25

    # Verify directly via a fresh sqlite connection.
    conn = sqlite3.connect(path)
    try:
        n = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        assert n == 25
    finally:
        conn.close()


def test_fields_persist_correctly(tmp_path):
    path = _db_path(tmp_path)

    async def run():
        backend = SqliteBackend(path)
        logger = AsyncAuditLogger(backend)
        await logger.start()
        await logger.log(
            _record("STOP", user="alice", rule="R-01", prompt="John Smith TFN")
        )
        await logger.stop(drain=True)
        await backend.connect()
        try:
            rows = await backend.fetch()
        finally:
            await backend.close()
        return rows

    rows = asyncio.run(run())
    assert len(rows) == 1
    r = rows[0]
    assert r.decision == "STOP"
    assert r.user_id == "alice"
    assert r.rule_triggered == "R-01"
    assert r.signals == ["sig:STOP"]
    assert r.prompt_hash == hash_prompt("John Smith TFN")


# --- monotonic ordering ------------------------------------------------------

def test_seq_is_monotonic(tmp_path):
    path = _db_path(tmp_path)

    async def run():
        backend = SqliteBackend(path)
        logger = AsyncAuditLogger(backend)
        await logger.start()
        for i in range(10):
            await logger.log(_record("ALLOW", user=f"u{i}"))
        await logger.stop(drain=True)

    asyncio.run(run())
    conn = sqlite3.connect(path)
    try:
        seqs = [r[0] for r in conn.execute("SELECT seq FROM audit_log ORDER BY seq")]
    finally:
        conn.close()
    assert seqs == sorted(seqs)
    assert seqs == list(range(seqs[0], seqs[0] + len(seqs)))


# --- raw prompt never written -----------------------------------------------

def test_raw_prompt_absent_from_storage(tmp_path):
    path = _db_path(tmp_path)
    secret = "postgres://admin:p4ssw0rd@prod-db:5432/lexaml"

    async def run():
        backend = SqliteBackend(path)
        logger = AsyncAuditLogger(backend)
        await logger.start()
        await logger.log(_record("STOP", rule="R-07", prompt=secret))
        await logger.stop(drain=True)

    asyncio.run(run())
    # Dump the entire DB file as text and assert the secret isn't there.
    raw = open(path, "rb").read().decode("latin-1")
    assert "p4ssw0rd" not in raw
    assert hash_prompt(secret) in raw


# --- append-only enforcement -------------------------------------------------

def test_update_and_delete_are_blocked(tmp_path):
    path = _db_path(tmp_path)

    async def run():
        backend = SqliteBackend(path)
        logger = AsyncAuditLogger(backend)
        await logger.start()
        await logger.log(_record("STOP", rule="R-01"))
        await logger.stop(drain=True)

    asyncio.run(run())
    conn = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE audit_log SET decision='ALLOW'")
            conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM audit_log")
            conn.commit()
        # Row is still there and unchanged.
        n = conn.execute("SELECT COUNT(*) FROM audit_log WHERE decision='STOP'").fetchone()[0]
        assert n == 1
    finally:
        conn.close()


# --- decision-type coverage --------------------------------------------------

def test_all_v1_decisions_logged(tmp_path):
    path = _db_path(tmp_path)

    async def run():
        backend = SqliteBackend(path)
        logger = AsyncAuditLogger(backend)
        await logger.start()
        for d in ("ALLOW", "STOP", "REDACT", "ESCALATE"):
            await logger.log(_record(d))
        await logger.stop(drain=True)
        await backend.connect()
        try:
            stops = await backend.fetch(decision="STOP")
            escs = await backend.fetch(decision="ESCALATE")
            total = await backend.count()
        finally:
            await backend.close()
        return total, len(stops), len(escs)

    total, stops, escs = asyncio.run(run())
    assert total == 4
    assert stops == 1
    assert escs == 1


# --- every decision type persists with the correct field ---------------------

def test_each_decision_type_persists_correctly(tmp_path):
    path = _db_path(tmp_path)

    async def run():
        backend = SqliteBackend(path)
        logger = AsyncAuditLogger(backend)
        await logger.start()
        for d in ("ALLOW", "STOP", "REDACT", "ESCALATE"):
            await logger.log(_record(d, rule="R-01" if d == "STOP" else ""))
        await logger.stop(drain=True)
        await backend.connect()
        try:
            out = {}
            for d in ("ALLOW", "STOP", "REDACT", "ESCALATE"):
                rows = await backend.fetch(decision=d)
                out[d] = rows
        finally:
            await backend.close()
        return out

    out = asyncio.run(run())
    for d, rows in out.items():
        assert len(rows) == 1, f"{d} not persisted exactly once"
        assert rows[0].decision == d


# --- flush + fail-closed availability ----------------------------------------

def test_flush_guarantees_persistence_before_stop(tmp_path):
    path = _db_path(tmp_path)

    async def run():
        backend = SqliteBackend(path)
        logger = AsyncAuditLogger(backend)
        await logger.start()
        for _ in range(5):
            await logger.log(_record("STOP", rule="R-07"))
        await logger.flush()                 # block until the worker drained
        count = await backend.count()        # queried while logger still running
        healthy = logger.healthy
        await logger.stop(drain=True)
        return count, healthy

    count, healthy = asyncio.run(run())
    assert count == 5
    assert healthy is True


class _FailingBackend(AuditBackend):
    """Backend that simulates a DB outage on connect and/or write."""

    def __init__(self, *, fail_connect: bool = False, fail_write: bool = False) -> None:
        self.fail_connect = fail_connect
        self.fail_write = fail_write

    async def connect(self) -> None:
        if self.fail_connect:
            raise OSError("db down")

    async def close(self) -> None:
        pass

    async def write(self, record: AuditRecord) -> None:
        await self.write_many((record,))

    async def write_many(self, records: Sequence[AuditRecord]) -> None:
        if self.fail_write:
            raise OSError("write failed")

    async def count(self) -> int:
        return 0

    async def fetch(self, **kwargs) -> list[AuditRecord]:
        return []


def test_write_failure_marks_unhealthy_and_require_available_raises(tmp_path):
    async def run():
        logger = AsyncAuditLogger(_FailingBackend(fail_write=True))
        await logger.start()
        assert logger.available is True          # healthy until a write fails
        await logger.log(_record("STOP", rule="R-07"))
        await logger.flush()                     # worker attempts the write, fails
        healthy_after = logger.healthy
        await logger.stop(drain=True)
        return healthy_after, logger

    healthy_after, logger = asyncio.run(run())
    assert healthy_after is False
    with pytest.raises(AuditUnavailable):
        logger.require_available()


def test_start_connect_failure_raises_audit_unavailable():
    async def run():
        logger = AsyncAuditLogger(_FailingBackend(fail_connect=True))
        with pytest.raises(AuditUnavailable):
            await logger.start()
        return logger

    logger = asyncio.run(run())
    assert logger.healthy is False
    with pytest.raises(AuditUnavailable):
        logger.require_available()
