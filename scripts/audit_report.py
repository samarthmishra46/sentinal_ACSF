"""Print the audit-log review queries for the demo (Day 3-4).

Runs the review queries Nikhil owns against an existing audit DB and prints them:
decision counts, all STOPs in the last hour, all escalations, and the latency
distribution (avg/p50/p95/p99). This is the "show Sumit the 7-year compliance
record" view for the demo.

    python scripts/audit_report.py --path ./sentinel_audit.db
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


def _print_rows(title, rows) -> None:
    print(f"\n=== {title} ({len(rows)}) ===")
    for r in rows:
        print(
            f"  [{r.decision:<8}] {r.timestamp}  user={r.user_id:<8} "
            f"rule={r.rule_triggered or '-':<5} policy={r.policy_triggered or '-':<5} "
            f"{r.latency_ms:>6.1f}ms"
        )


async def main(path: str) -> None:
    backend = SqliteBackend(path)
    await backend.connect()
    try:
        print(f"audit DB: {path}")
        counts = await queries.decision_counts(backend)
        print(f"\n=== decision counts ===\n  {counts}")
        _print_rows("STOP decisions in the last hour", await queries.stops_last_hour(backend))
        _print_rows("all escalations", await queries.escalations(backend))
        stats = await queries.latency_stats(backend)
        print(f"\n=== latency distribution ===\n  {stats}")
    finally:
        await backend.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Print audit-log review queries.")
    p.add_argument("--path", default="sentinel_audit.db", help="SQLite audit DB path")
    args = p.parse_args()
    asyncio.run(main(args.path))
