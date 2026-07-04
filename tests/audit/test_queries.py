"""Tests for the read-side audit query helpers (Day 3 demo queries)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from app.audit import AuditRecord, SqliteBackend, queries


def _rec(decision: str, *, user: str = "u1", latency: float = 10.0,
         ts: str | None = None, rule: str = "") -> AuditRecord:
    r = AuditRecord.new(
        user_id=user, role="Engineer", decision=decision, prompt="p",
        actor_type="A-01", rule_triggered=rule, latency_ms=latency,
    )
    if ts is not None:
        r.timestamp = ts  # AuditRecord isn't frozen; override for time-window tests
    return r


def _run_with(records):
    """Seed a temp DB with records and return a connected backend inside a loop."""
    async def _seed(path):
        b = SqliteBackend(path)
        await b.connect()
        await b.write_many(records)
        return b
    return _seed


def test_stops_last_hour_excludes_old(tmp_path):
    path = str(tmp_path / "q.db")
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()

    async def run():
        b = SqliteBackend(path)
        await b.connect()
        await b.write_many([
            _rec("STOP", rule="R-07"),               # now -> in window
            _rec("STOP", rule="R-01", ts=old_ts),    # 3h ago -> excluded
            _rec("ALLOW"),                            # wrong decision
        ])
        stops = await queries.stops_last_hour(b)
        await b.close()
        return stops

    stops = asyncio.run(run())
    assert len(stops) == 1
    assert stops[0].rule_triggered == "R-07"


def test_escalations(tmp_path):
    path = str(tmp_path / "q.db")

    async def run():
        b = SqliteBackend(path)
        await b.connect()
        await b.write_many([_rec("ESCALATE"), _rec("ALLOW"), _rec("ESCALATE")])
        escs = await queries.escalations(b)
        await b.close()
        return escs

    assert len(asyncio.run(run())) == 2


def test_decision_counts(tmp_path):
    path = str(tmp_path / "q.db")

    async def run():
        b = SqliteBackend(path)
        await b.connect()
        await b.write_many([
            _rec("ALLOW"), _rec("STOP"), _rec("STOP"), _rec("ESCALATE"),
        ])
        counts = await queries.decision_counts(b)
        await b.close()
        return counts

    assert asyncio.run(run()) == {"ALLOW": 1, "STOP": 2, "ESCALATE": 1}


def test_latency_stats(tmp_path):
    path = str(tmp_path / "q.db")

    async def run():
        b = SqliteBackend(path)
        await b.connect()
        await b.write_many([_rec("ALLOW", latency=l) for l in (10, 20, 30, 40, 100)])
        stats = await queries.latency_stats(b)
        await b.close()
        return stats

    stats = asyncio.run(run())
    assert stats["count"] == 5
    assert stats["min_ms"] == 10
    assert stats["max_ms"] == 100
    assert stats["avg_ms"] == 40.0
    assert stats["p50_ms"] == 30    # nearest-rank: ceil(.50*5)=3 -> idx2
    assert stats["p95_ms"] == 100   # ceil(.95*5)=5 -> idx4


def test_latency_stats_empty(tmp_path):
    path = str(tmp_path / "q.db")

    async def run():
        b = SqliteBackend(path)
        await b.connect()
        stats = await queries.latency_stats(b)
        await b.close()
        return stats

    assert asyncio.run(run()) == {"count": 0}


def test_for_user(tmp_path):
    path = str(tmp_path / "q.db")

    async def run():
        b = SqliteBackend(path)
        await b.connect()
        await b.write_many([
            _rec("ALLOW", user="alice"), _rec("STOP", user="bob"),
            _rec("ESCALATE", user="alice"),
        ])
        rows = await queries.for_user(b, "alice")
        await b.close()
        return rows

    rows = asyncio.run(run())
    assert len(rows) == 2
    assert {r.user_id for r in rows} == {"alice"}


# --- Day 4: latency recorded on every record ---------------------------------

def test_latency_recorded_on_every_record(tmp_path):
    path = str(tmp_path / "q.db")

    async def run():
        b = SqliteBackend(path)
        await b.connect()
        await b.write_many([_rec("ALLOW", latency=l) for l in (5.0, 12.0, 30.0)])
        missing = await queries.records_without_latency(b)
        await b.close()
        return missing

    assert asyncio.run(run()) == []          # every record has a measured latency


def test_records_without_latency_flags_zero(tmp_path):
    path = str(tmp_path / "q.db")

    async def run():
        b = SqliteBackend(path)
        await b.connect()
        await b.write_many([_rec("ALLOW", latency=10.0), _rec("STOP", latency=0.0)])
        missing = await queries.records_without_latency(b)
        await b.close()
        return missing

    missing = asyncio.run(run())
    assert len(missing) == 1
    assert missing[0].decision == "STOP"


def test_format_records_table_has_columns_and_no_raw_prompt(tmp_path):
    path = str(tmp_path / "q.db")

    async def run():
        b = SqliteBackend(path)
        await b.connect()
        await b.write_many([_rec("STOP", rule="R-07", latency=9.9)])
        recs = await queries.all_records(b)
        await b.close()
        return recs

    table = queries.format_records_table(asyncio.run(run()))
    assert "DECISION" in table and "LATENCY" in table
    assert "STOP" in table and "R-07" in table
    assert "9.9ms" in table
