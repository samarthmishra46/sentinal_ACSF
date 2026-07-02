"""End-to-end demo of the audit subsystem (proves the Day-1 gate).

Writes one AuditRecord per decision type through the real AsyncAuditLogger, then
runs the three review queries Nikhil will show on Day 3/4:

  1. all decisions this session
  2. all STOP decisions
  3. all ESCALATE decisions

Run it::

    python scripts/audit_demo.py            # uses a throwaway temp SQLite DB

This mirrors a real request flow: each "request" yields a Decision-like outcome,
which becomes an AuditRecord (raw prompt hashed, never stored), is enqueued, and
the background worker persists it to the append-only table.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

# Allow running as a plain script (python scripts/audit_demo.py).
import sys

# Windows consoles default to cp1252; make stdout UTF-8 so output never crashes.
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - older interpreters / redirected stdout
    pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.audit import AsyncAuditLogger, AuditRecord, SqliteBackend  # noqa: E402


# Four illustrative requests, each tied to a real rule from the policy doc.
SAMPLE_REQUESTS = [
    dict(
        user_id="u-aisha",
        role="Engineer",
        actor_type="A-01",
        service="dvs-verification",
        prompt="How does our DVS verification flow handle failed identity checks?",
        decision="ALLOW",
        rule_triggered="",
        policy_triggered="",
        reason="Safe engineering question; all stages passed.",
        signals=[],
    ),
    dict(
        user_id="u-aisha",
        role="Engineer",
        actor_type="A-01",
        service="risk-scoring",
        prompt="John Smith, TFN 123-456-789, DOB 15/03/1985. Why is this scoring wrong?",
        decision="STOP",
        rule_triggered="R-01",
        policy_triggered="P-01",
        reason="Customer PII (TFN + name + DOB) detected; blocked before model (R-01).",
        signals=["pii:TFN", "pii:DOB", "pii:NAME"],
    ),
    dict(
        user_id="u-mark",
        role="Engineer",
        actor_type="A-01",
        service="db",
        prompt="Connection string: postgres://lexaml_admin:p4ssw0rd@prod-db.internal:5432/lexaml_prod",
        decision="STOP",
        rule_triggered="R-07",
        policy_triggered="P-01",
        reason="Database credential detected; blocked and flagged for rotation (R-07).",
        signals=["secret:postgres_uri"],
    ),
    dict(
        user_id="u-priya",
        role="Engineer",
        actor_type="A-01",
        service="reporting",
        prompt="Write a SQL query to export all customer CDD records into a CSV.",
        decision="ESCALATE",
        rule_triggered="R-05",
        policy_triggered="P-05",
        reason="Bulk extraction pattern; held for human reviewer (R-05).",
        signals=["bulk:export_all", "bulk:no_where_clause"],
    ),
]


def _print_records(title: str, records: list[AuditRecord]) -> None:
    print(f"\n=== {title} ({len(records)} rows) ===")
    for r in records:
        print(
            f"  [{r.decision:<8}] {r.timestamp}  user={r.user_id:<8} "
            f"rule={r.rule_triggered or '-':<5} hash={r.prompt_hash[:12]}...  {r.reason}"
        )


async def main() -> None:
    tmpdir = tempfile.mkdtemp(prefix="sentinel_demo_")
    db_path = Path(tmpdir) / "sentinel_audit.db"

    backend = SqliteBackend(db_path)
    logger = AsyncAuditLogger(backend)
    await logger.start()

    # Simulate a request flow: each request -> AuditRecord -> enqueue.
    for req in SAMPLE_REQUESTS:
        record = AuditRecord.new(
            user_id=req["user_id"],
            role=req["role"],
            decision=req["decision"],
            prompt=req["prompt"],          # hashed inside new(); raw text dropped
            service=req["service"],
            reason=req["reason"],
            actor_type=req["actor_type"],
            rule_triggered=req["rule_triggered"],
            policy_triggered=req["policy_triggered"],
            latency_ms=12.5,
            signals=req["signals"],
        )
        await logger.log(record)

    # Drain + flush, then read back through the same backend.
    await logger.stop(drain=True)
    print(f"audit DB: {db_path}")
    print(f"records persisted: {logger.written}")

    await backend.connect()
    try:
        _print_records("Query 1 - all decisions this session", await backend.fetch())
        _print_records(
            "Query 2 - all STOP decisions",
            await backend.fetch(decision="STOP"),
        )
        _print_records(
            "Query 3 - all ESCALATE decisions",
            await backend.fetch(decision="ESCALATE"),
        )

        # Prove tamper-evidence: the append-only trigger rejects mutation.
        print("\n=== Append-only check ===")
        try:
            await backend._run(  # type: ignore[attr-defined]
                lambda: backend._conn.execute(  # type: ignore[union-attr]
                    "UPDATE audit_log SET decision='ALLOW' WHERE decision='STOP'"
                )
            )
            print("  [FAIL] UPDATE unexpectedly succeeded (append-only NOT enforced)")
        except Exception as exc:  # noqa: BLE001
            print(f"  [OK] UPDATE blocked: {exc}")
    finally:
        await backend.close()


if __name__ == "__main__":
    asyncio.run(main())
