"""Vercel serverless entrypoint for the Sentinel PEP.

Vercel's Python runtime serves the module-level ``app`` (an ASGI FastAPI
instance); vercel.json rewrites every route to this single function.

Two runtime facts about Vercel this shim handles:
  * The function runs from the ``api/`` dir, so the repo root must be on
    sys.path for ``import app.main`` to resolve.
  * The filesystem is read-only except ``/tmp``; the audit log's default
    SQLite path would fail, so we point DB_URL at ``/tmp`` (ephemeral, which
    is fine — a serverless audit DB is throwaway anyway).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DB_URL", "sqlite:////tmp/audit.db")

from app.main import app  # noqa: E402  (import after sys.path / env setup)
