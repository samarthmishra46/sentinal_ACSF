"""Tests for the behavioural / session tracker and its pipeline stage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.config import settings
from app.pdp.behaviour.tracker import BehaviourTracker


def _t(h=12, m=0):
    return datetime(2026, 7, 24, h, m, tzinfo=timezone.utc)


def test_normal_usage_not_flagged():
    tr = BehaviourTracker(max_queries_per_hour=60)
    for i in range(10):
        v = tr.record_and_check("u1", f"question {i}", ["svc"], now=_t(12, i))
    assert not v.anomalous


def test_query_rate_flagged():
    tr = BehaviourTracker(max_queries_per_hour=20)
    v = None
    for i in range(25):
        v = tr.record_and_check("u1", "q", ["svc"], now=_t(12, 0) + timedelta(seconds=i))
    assert v.anomalous and v.feature == "query_rate"


def test_distinct_customers_flagged():
    tr = BehaviourTracker(max_queries_per_hour=1000, max_distinct_customers=5)
    v = None
    for i in range(8):
        v = tr.record_and_check("u1", f"look up customer-{1000+i}", ["svc"],
                                now=_t(12, 0) + timedelta(seconds=i))
    assert v.anomalous and v.feature == "distinct_customers"


def test_window_prunes_old_events():
    tr = BehaviourTracker(window_seconds=3600, max_queries_per_hour=5)
    # 5 now, then 5 more an hour+ later — old ones should have aged out.
    for i in range(5):
        tr.record_and_check("u1", "q", ["svc"], now=_t(12, 0) + timedelta(seconds=i))
    v = tr.record_and_check("u1", "q", ["svc"], now=_t(14, 0))
    assert not v.anomalous  # window slid; only 1 event in the new hour


def test_escalate_streak_flagged():
    tr = BehaviourTracker(max_escalate_streak=3)
    v = None
    for _ in range(4):
        v = tr.note_decision("u1", escalated_or_blocked=True)
    assert v.anomalous and v.feature == "escalate_streak"


def test_escalate_streak_resets_on_clean():
    tr = BehaviourTracker(max_escalate_streak=3)
    for _ in range(3):
        tr.note_decision("u1", True)
    tr.note_decision("u1", False)                # clean request resets
    v = tr.note_decision("u1", True)
    assert not v.anomalous


def test_customer_id_extraction():
    ids = BehaviourTracker.extract_customer_ids(
        "check customer-1042 and account 5567123 and PAN ABCDE1234F")
    assert len(ids) >= 2


def test_users_are_isolated():
    tr = BehaviourTracker(max_queries_per_hour=5)
    for i in range(6):
        tr.record_and_check("u1", "q", ["svc"], now=_t(12, 0) + timedelta(seconds=i))
    v = tr.record_and_check("u2", "q", ["svc"], now=_t(12, 0))
    assert not v.anomalous  # u2 unaffected by u1's volume


# ── Stage integration ───────────────────────────────────────────────────────

def test_stage_noop_when_disabled(monkeypatch):
    from app.pdp import factory
    monkeypatch.setattr(settings, "BEHAVIOUR_ENABLED", False)
    ctx = type("C", (), {"user_id": "u", "owned_services": ["svc"], "timestamp": _t()})()
    assert factory.behaviour_stage(ctx, "hi", None) is None


def test_stage_escalates_on_anomaly(monkeypatch):
    from app.pdp import factory
    from app.pdp.decision import Disposition
    monkeypatch.setattr(settings, "BEHAVIOUR_ENABLED", True)
    monkeypatch.setattr(settings, "BEHAVIOUR_MAX_QUERIES_PER_HOUR", 3)
    factory._behaviour_tracker = None  # rebuild with the patched threshold
    ctx = type("C", (), {"user_id": "ux", "owned_services": ["svc"], "timestamp": _t()})()
    d = None
    for _ in range(5):
        d = factory.behaviour_stage(ctx, "q", None)
    assert d is not None and d.disposition is Disposition.ESCALATE
    assert d.decisive_signal.rule_id == "R-22"
    factory._behaviour_tracker = None  # don't leak state to other tests
