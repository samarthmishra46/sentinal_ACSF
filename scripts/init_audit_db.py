"""Initialise the Sentinel audit database.

Day 1 task: "Set up PostgreSQL locally — create sentinel_audit database" and
apply the append-only schema. This script does both, and also supports the SQLite
fallback so the subsystem is runnable on a machine without PostgreSQL.

Usage
-----
SQLite (fallback, no dependencies)::

    python scripts/init_audit_db.py --backend sqlite --path ./sentinel_audit.db

PostgreSQL (production target; requires a reachable server + asyncpg)::

    python scripts/init_audit_db.py --backend pg \
        --dsn postgres://admin:pw@localhost:5432/postgres \
        --db sentinel_audit

For PostgreSQL the script connects to the server, creates the target database if
absent, then applies app/audit/schema.sql inside it.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

_AUDIT_DIR = Path(__file__).resolve().parent.parent / "app" / "audit"
_SQLITE_SCHEMA = _AUDIT_DIR / "schema_sqlite.sql"
_PG_SCHEMA = _AUDIT_DIR / "schema.sql"


def init_sqlite(path: str) -> None:
    schema = _SQLITE_SCHEMA.read_text(encoding="utf-8")
    conn = sqlite3.connect(path)
    try:
        conn.executescript(schema)
        conn.commit()
        n_idx = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' "
            "AND tbl_name='audit_log'"
        ).fetchone()[0]
    finally:
        conn.close()
    print(f"[ok] SQLite audit DB ready at {path} (audit_log table, {n_idx} indexes)")
    print("     append-only triggers installed: UPDATE/DELETE will raise.")


def init_postgres(dsn: str, db_name: str) -> None:
    try:
        import asyncpg  # type: ignore  # noqa: F401
    except ImportError:
        sys.exit(
            "asyncpg is not installed. Run `pip install -r requirements-audit.txt` "
            "first, or use --backend sqlite for the Day 1-2 fallback."
        )
    import asyncio

    async def _run() -> None:
        import asyncpg  # type: ignore

        # 1) Connect to the admin/maintenance DB and create the target if needed.
        admin = await asyncpg.connect(dsn)
        try:
            exists = await admin.fetchval(
                "SELECT 1 FROM pg_database WHERE datname = $1", db_name
            )
            if not exists:
                # CREATE DATABASE cannot run inside a transaction block.
                await admin.execute(f'CREATE DATABASE "{db_name}"')
                print(f"[ok] created database {db_name}")
            else:
                print(f"[skip] database {db_name} already exists")
        finally:
            await admin.close()

        # 2) Connect to the target DB and apply the schema.
        base, _, _ = dsn.rpartition("/")
        target_dsn = f"{base}/{db_name}"
        conn = await asyncpg.connect(target_dsn)
        try:
            await conn.execute(_PG_SCHEMA.read_text(encoding="utf-8"))
        finally:
            await conn.close()
        print(f"[ok] applied schema.sql to {db_name} (append-only audit_log ready)")

    asyncio.run(_run())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Initialise the Sentinel audit DB.")
    p.add_argument("--backend", choices=("sqlite", "pg"), required=True)
    p.add_argument("--path", default="sentinel_audit.db", help="SQLite file path")
    p.add_argument("--dsn", help="PostgreSQL admin DSN (connects to create the DB)")
    p.add_argument("--db", default="sentinel_audit", help="PostgreSQL database name")
    args = p.parse_args(argv)

    if args.backend == "sqlite":
        init_sqlite(args.path)
    else:
        if not args.dsn:
            p.error("--dsn is required for --backend pg")
        init_postgres(args.dsn, args.db)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
