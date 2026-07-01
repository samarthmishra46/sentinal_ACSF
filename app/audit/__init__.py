"""Audit-log subsystem (Nikhil — Secrets Detector + Audit Log).

Public surface for the rest of Sentinel. Teammates should import from here, not
from the submodules, so the internal layout can change without breaking callers::

    from app.audit import AuditRecord, AsyncAuditLogger, SqliteBackend, hash_prompt

The append-only, tamper-evident, 7-year-retention requirements come from the
"Audit trail integration with Lex-AML" section of the policy document. The
PostgreSQL target comes from gap R-G4 in the Master Analysis; the SQLite backend
is the documented Day 1-2 fallback (same interface, different driver).
"""

from .models import (
    AuditRecord,
    DECISIONS,
    ACTOR_TYPES,
    POLICY_VERSION,
    hash_prompt,
)
from .backends import AuditBackend, SqliteBackend, PostgresBackend
from .logger import AsyncAuditLogger

__all__ = [
    "AuditRecord",
    "DECISIONS",
    "ACTOR_TYPES",
    "POLICY_VERSION",
    "hash_prompt",
    "AuditBackend",
    "SqliteBackend",
    "PostgresBackend",
    "AsyncAuditLogger",
]
