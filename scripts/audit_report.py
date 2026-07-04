"""Audit-log demo report (Nikhil, Day 4).

The "show Sumit the 7-year compliance record" view. Runs the demo review queries
against an existing audit DB and prints them, plus a full audit-log table and a
latency-completeness check.

    python scripts/audit_report.py --path ./sentinel_audit.db

The 3 demo queries (sprint plan): all decisions this session, all STOPs, all
escalations. Plus: latency distribution + verification that every record carries
a measured latency_ms.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.audit import SqliteBackend, queries  # noqa: E402


def _section(title: str) -> None:
    print(f"\n{'=' * 70}\n {title}\n{'=' * 70}")


async def main(path: str) -> None:
    backend = SqliteBackend(path)
    await backend.connect()
    try:
        print(f"audit DB: {path}")

        # --- Demo query 1: all decisions this session (the full table) --------
        records = await queries.all_records(backend)
        _section(f"Query 1 - all decisions this session ({len(records)})")
        print(queries.format_records_table(records))
        print(f"\n  decision counts: {await queries.decision_counts(backend)}")

        # --- Demo query 2: all STOP decisions ---------------------------------
        stops = await queries.by_decision(backend, "STOP")
        _section(f"Query 2 - all STOP decisions ({len(stops)})")
        print(queries.format_records_table(stops) if stops else "  (none)")

        # --- Demo query 3: all escalations ------------------------------------
        escs = await queries.escalations(backend)
        _section(f"Query 3 - all ESCALATE decisions ({len(escs)})")
        print(queries.format_records_table(escs) if escs else "  (none)")

        # --- Latency distribution + verification ------------------------------
        _section("Latency")
        print(f"  distribution: {await queries.latency_stats(backend)}")
        missing = await queries.records_without_latency(backend)
        total = len(records)
        ok = total - len(missing)
        status = "[OK]" if not missing else "[FAIL]"
        print(f"  {status} latency_ms recorded on {ok}/{total} records"
              + (f" ({len(missing)} missing)" if missing else ""))
    finally:
        await backend.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Print audit-log demo queries.")
    p.add_argument("--path", default="sentinel_audit.db", help="SQLite audit DB path")
    args = p.parse_args()
    asyncio.run(main(args.path))
