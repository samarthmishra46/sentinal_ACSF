# RYAN-DAY3
"""Tests for the Day-3 audit integration + escalation notification (Ryan).

Covers the three Day-3 seams in the PEP:
  * ``LoggerAuditSink`` — the swap from the console sink to Nikhil's
    ``AsyncAuditLogger``: unstarted fallback, and a real record persisted to the
    SQLite backend when ``record()`` is called from a worker thread (the exact
    shape of Starlette's threadpool running the sync /v1/chat route).
  * Ingress fail-closed on audit health — "if the DB is down, ESCALATE rather
    than answer un-audited" (sprint plan, Day 3).
  * ``EscalationQueue`` Slack notification — fires when the webhook is
    configured, and a Slack outage never raises into the request path.
"""
from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timezone

import httpx
import pytest

from app.audit import AsyncAuditLogger, SqliteBackend, hash_prompt
from app.escalation import queue as escalation_queue
from app.identity.eim_client import EIMClient
from app.pdp.decision import Decision, Disposition, Signal
from app.pep import audit_hook, ingress
from app.pep.audit_hook import LoggerAuditSink
from app.policy.models import Snapshot


def _stop_decision() -> Decision:
    sig = Signal(
        detector="secrets",
        rule_id="R-07",
        disposition=Disposition.STOP,
        reason="credential material detected",
    )
    return Decision(Disposition.STOP, "credential material detected", (sig,))


def _snapshot() -> Snapshot:
    return Snapshot(
        version="test",
        created_at=datetime.now(timezone.utc),
        catalog={"R-07": {"policy_id": "P-03"}},
    )


# --- LoggerAuditSink -------------------------------------------------------- #


def test_unstarted_sink_falls_back_to_console(capsys):
    """Without lifespan startup (bare TestClient) the sink must not need a loop."""
    sink = LoggerAuditSink(AsyncAuditLogger(SqliteBackend(":memory:")))
    sink.record(
        _stop_decision(),
        {"decision": "STOP", "reason": "r", "response": None},
        prompt="postgres://user:hunter2@db/prod",
        ctx=None,
        latency_ms=1.0,
        snapshot=None,
    )
    assert "[AUDIT]" in capsys.readouterr().out


def test_started_sink_persists_record_from_worker_thread(tmp_path):
    """A record enqueued from a threadpool thread lands in the SQLite table."""
    db = tmp_path / "audit.db"
    ctx = EIMClient().get_context("u-001")
    prompt = "postgres://user:hunter2@db/prod why does this fail?"
    decision = _stop_decision()

    async def scenario() -> None:
        sink = LoggerAuditSink(AsyncAuditLogger(SqliteBackend(db)))
        await sink.start()
        # Same execution shape as production: sync route code on a worker thread.
        await asyncio.to_thread(
            sink.record,
            decision,
            {"decision": "STOP", "reason": "r", "response": None},
            prompt=prompt,
            ctx=ctx,
            latency_ms=4.2,
            snapshot=_snapshot(),
        )
        # Let the call_soon_threadsafe callback enqueue before the drain sentinel.
        await asyncio.sleep(0.05)
        await sink.stop()

    asyncio.run(scenario())

    con = sqlite3.connect(db)
    rows = con.execute(
        "SELECT user_id, role, decision, rule_triggered, policy_triggered,"
        " prompt_hash, actor_type FROM audit_log"
    ).fetchall()
    con.close()
    assert rows == [
        ("u-001", "Engineer", "STOP", "R-07", "P-03", hash_prompt(prompt), "A-01")
    ]


def test_sqlite_path_parses_settings_url(monkeypatch):
    monkeypatch.setattr(audit_hook.settings, "DB_URL", "sqlite:////tmp/x/audit.db")
    assert str(audit_hook._sqlite_path()) == "/tmp/x/audit.db"


# --- ingress fail-closed on audit health ------------------------------------ #


def test_ingress_escalates_when_audit_unhealthy(monkeypatch, capsys):
    monkeypatch.setattr(audit_hook, "is_healthy", lambda: False)

    def _must_not_run(ctx, prompt):  # the PDP/AI must never see the request
        raise AssertionError("pipeline.evaluate called while audit was down")

    monkeypatch.setattr(ingress._pipeline, "evaluate", _must_not_run)
    body = ingress.handle_request("What is DVS verification?", "u-001")
    assert body["decision"] == "ESCALATE"
    assert body["response"] == "Your request is under review."
    # Routed through enforcement so the escalation queue fired too.
    assert '"event": "ESCALATION"' in capsys.readouterr().out


def test_ingress_answers_when_audit_healthy(monkeypatch):
    monkeypatch.setattr(audit_hook, "is_healthy", lambda: True)
    body = ingress.handle_request("What is DVS verification?", "u-001")
    assert body["decision"] == "ALLOW"


# --- EscalationQueue Slack notification -------------------------------------- #


def _escalation() -> tuple:
    ctx = EIMClient().get_context("u-002")
    sig = Signal(
        detector="intent",
        rule_id="R-05",
        disposition=Disposition.ESCALATE,
        reason="bulk export of CDD records",
    )
    return ctx, Decision(Disposition.ESCALATE, "bulk export of CDD records", (sig,))


def test_slack_notification_posts_summary(monkeypatch):
    ctx, decision = _escalation()
    calls: dict = {}

    class _Resp:
        def raise_for_status(self) -> None: ...

    def fake_post(url, json=None, timeout=None):
        calls.update(url=url, json=json, timeout=timeout)
        return _Resp()

    monkeypatch.setattr(
        escalation_queue.settings, "SLACK_WEBHOOK", "https://hooks.slack.test/T/B/x"
    )
    monkeypatch.setattr(escalation_queue.httpx, "post", fake_post)
    escalation_queue.EscalationQueue().enqueue("export all CDD to csv", ctx, decision)

    assert calls["url"] == "https://hooks.slack.test/T/B/x"
    text = calls["json"]["text"]
    assert "Sentinel escalation" in text and "R-05" in text and "u-002" in text
    assert calls["timeout"] == pytest.approx(2.0)


def test_slack_disabled_without_webhook(monkeypatch):
    ctx, decision = _escalation()
    monkeypatch.setattr(escalation_queue.settings, "SLACK_WEBHOOK", None)

    def _must_not_post(*a, **k):
        raise AssertionError("httpx.post called with no webhook configured")

    monkeypatch.setattr(escalation_queue.httpx, "post", _must_not_post)
    escalation_queue.EscalationQueue().enqueue("p", ctx, decision)  # no raise


def test_slack_failure_never_breaks_request_path(monkeypatch, capsys):
    ctx, decision = _escalation()
    monkeypatch.setattr(
        escalation_queue.settings, "SLACK_WEBHOOK", "https://hooks.slack.test/T/B/x"
    )

    def _down(*a, **k):
        raise httpx.ConnectError("slack is down")

    monkeypatch.setattr(escalation_queue.httpx, "post", _down)
    escalation_queue.EscalationQueue().enqueue("p", ctx, decision)  # no raise
    assert "Slack notify failed" in capsys.readouterr().out
