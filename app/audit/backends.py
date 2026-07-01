"""Storage backends for the audit log.

One interface, two implementations:

* :class:`SqliteBackend` — stdlib ``sqlite3`` run through a thread executor so it
  never blocks the event loop. Zero external dependencies, so this is what the
  tests and the local demo use. It is the documented Day 1-2 fallback.
* :class:`PostgresBackend` — ``asyncpg`` connection pool, the V1 production
  target (Master Analysis gap R-G4). Importing ``asyncpg`` is deferred to
  instantiation so this module imports fine on a machine without it.

Both expose the same coroutine surface, so :class:`~app.audit.logger.AsyncAuditLogger`
is identical regardless of which one it holds — "only the driver changes".
"""

from __future__ import annotations

import asyncio
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Sequence

from .models import COLUMNS, AuditRecord

_SCHEMA_DIR = Path(__file__).resolve().parent
_SQLITE_SCHEMA = _SCHEMA_DIR / "schema_sqlite.sql"
_PG_SCHEMA = _SCHEMA_DIR / "schema.sql"

# Column list used in INSERT statements (everything the app supplies; `seq` and
# `inserted_at` are filled by the DB).
_INSERT_COLS = ", ".join(COLUMNS)


class AuditBackend(ABC):
    """Abstract storage for audit records.

    Lifecycle: ``await connect()`` once, ``await write()/write_many()`` per
    record(s), ``await close()`` on shutdown. ``count()`` and ``fetch()`` exist
    for verification, demos, and Day-3/4 review queries.
    """

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def close(self) -> None: ...

    @abstractmethod
    async def write(self, record: AuditRecord) -> None: ...

    async def write_many(self, records: Sequence[AuditRecord]) -> None:
        """Default: write one at a time. Backends may override for batching."""
        for r in records:
            await self.write(r)

    @abstractmethod
    async def count(self) -> int: ...

    @abstractmethod
    async def fetch(self, where: str = "", params: Sequence[Any] = ()) -> list[AuditRecord]:
        """Return records matching an optional WHERE clause, newest first.

        ``where`` is a raw SQL fragment *without* the ``WHERE`` keyword. Callers
        are trusted internal code (demo/review queries); always parameterise
        user-derived values via ``params``.
        """


# -----------------------------------------------------------------------------
# SQLite backend (stdlib, executor-driven) — default for tests + local demo.
# -----------------------------------------------------------------------------
class SqliteBackend(AuditBackend):
    def __init__(self, path: str | Path = "sentinel_audit.db") -> None:
        # ":memory:" is supported but note each connection gets its own DB, so
        # for tests prefer a temp file.
        self.path = str(path)
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()  # serialise access to the single connection

    async def connect(self) -> None:
        await self._run(self._connect_sync)

    def _connect_sync(self) -> None:
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._conn.executescript(_SQLITE_SCHEMA.read_text(encoding="utf-8"))
        self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._run(self._conn.close)
            self._conn = None

    async def write(self, record: AuditRecord) -> None:
        await self.write_many((record,))

    async def write_many(self, records: Sequence[AuditRecord]) -> None:
        rows = [r.to_row() for r in records]

        def _insert() -> None:
            assert self._conn is not None
            placeholders = ", ".join("?" for _ in COLUMNS)
            self._conn.executemany(
                f"INSERT INTO audit_log ({_INSERT_COLS}) VALUES ({placeholders})",
                rows,
            )
            self._conn.commit()

        async with self._lock:
            await self._run(_insert)

    async def count(self) -> int:
        def _count() -> int:
            assert self._conn is not None
            cur = self._conn.execute("SELECT COUNT(*) FROM audit_log")
            return int(cur.fetchone()[0])

        async with self._lock:
            return await self._run(_count)

    async def fetch(self, where: str = "", params: Sequence[Any] = ()) -> list[AuditRecord]:
        def _fetch() -> list[AuditRecord]:
            assert self._conn is not None
            sql = f"SELECT {_INSERT_COLS} FROM audit_log"
            if where:
                sql += f" WHERE {where}"
            sql += " ORDER BY seq DESC"
            cur = self._conn.execute(sql, tuple(params))
            return [AuditRecord.from_row(row) for row in cur.fetchall()]

        async with self._lock:
            return await self._run(_fetch)

    @staticmethod
    async def _run(fn, *args):
        """Run a blocking sqlite call on the default thread-pool executor."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, fn, *args)


# -----------------------------------------------------------------------------
# PostgreSQL backend (asyncpg) — production target. Documented, not exercised on
# this machine (no Postgres / no asyncpg installed).
# -----------------------------------------------------------------------------
class PostgresBackend(AuditBackend):
    def __init__(self, dsn: str, *, min_size: int = 1, max_size: int = 10) -> None:
        self.dsn = dsn
        self._min_size = min_size
        self._max_size = max_size
        self._pool: Any = None

    async def connect(self) -> None:
        asyncpg = _require_asyncpg()
        self._pool = await asyncpg.create_pool(
            self.dsn, min_size=self._min_size, max_size=self._max_size
        )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def write(self, record: AuditRecord) -> None:
        await self.write_many((record,))

    async def write_many(self, records: Sequence[AuditRecord]) -> None:
        assert self._pool is not None, "connect() first"
        # asyncpg uses $1..$N placeholders and native types; pass signals as a
        # JSON string cast to jsonb. Build rows in COLUMNS order.
        placeholders = ", ".join(f"${i + 1}" for i in range(len(COLUMNS)))
        sql = (
            f"INSERT INTO sentinel_audit.audit_log ({_INSERT_COLS}) "
            f"VALUES ({placeholders})"
        )
        rows = [self._pg_row(r) for r in records]
        async with self._pool.acquire() as conn:
            await conn.executemany(sql, rows)

    @staticmethod
    def _pg_row(r: AuditRecord) -> tuple[Any, ...]:
        # to_row() already JSON-encodes signals; asyncpg will bind that string to
        # the JSONB column. request_id/ts are passed as strings and cast by PG.
        return r.to_row()

    async def count(self) -> int:
        assert self._pool is not None, "connect() first"
        async with self._pool.acquire() as conn:
            return int(await conn.fetchval("SELECT COUNT(*) FROM sentinel_audit.audit_log"))

    async def fetch(self, where: str = "", params: Sequence[Any] = ()) -> list[AuditRecord]:
        assert self._pool is not None, "connect() first"
        sql = f"SELECT {_INSERT_COLS} FROM sentinel_audit.audit_log"
        if where:
            sql += f" WHERE {where}"
        sql += " ORDER BY seq DESC"
        async with self._pool.acquire() as conn:
            records = await conn.fetch(sql, *params)
        return [AuditRecord.from_row(tuple(rec.values())) for rec in records]


def _require_asyncpg():
    try:
        import asyncpg  # type: ignore

        return asyncpg
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise RuntimeError(
            "PostgresBackend requires the 'asyncpg' package. Install it with "
            "`pip install -r requirements-audit.txt`, or use SqliteBackend for "
            "the Day 1-2 fallback."
        ) from exc
