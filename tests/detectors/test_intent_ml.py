"""Unit tests for the domain-intent classifier detector — monkeypatched, no model."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.config import settings
from app.pdp.decision import Disposition
from app.pdp.detectors import intent_ml as mod
from app.pdp.detectors.intent_ml import IntentMLDetector
from app.policy.models import Snapshot

CATALOG = {
    "R-03": {"id": "R-03", "disposition": "STOP"},
    "R-05": {"id": "R-05", "disposition": "ESCALATE"},
    "R-09": {"id": "R-09", "disposition": "STOP"},
}


@pytest.fixture
def det() -> IntentMLDetector:
    return IntentMLDetector()


@pytest.fixture
def snap() -> Snapshot:
    return Snapshot(version="t", created_at=datetime.now(timezone.utc), catalog=CATALOG)


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    monkeypatch.setattr(settings, "INTENT_ML_ENABLED", True)
    monkeypatch.setattr(settings, "INTENT_STOP_THRESHOLD", 0.70)
    monkeypatch.setattr(settings, "INTENT_ESCALATE_THRESHOLD", 0.45)
    yield


def test_confident_stop_rule_stops(det, snap, monkeypatch):
    monkeypatch.setattr(mod, "_predict", lambda p: ("R-03", 0.92))
    sig = det.scan(None, "skip the kyc check", snap)
    assert sig is not None and sig.disposition is Disposition.STOP
    assert sig.rule_id == "R-03"
    assert sig.metadata["source"] == "intent_ml"


def test_confident_escalate_rule_escalates_not_stops(det, snap, monkeypatch):
    # R-05 is ESCALATE-class: even at high confidence it must not STOP.
    monkeypatch.setattr(mod, "_predict", lambda p: ("R-05", 0.95))
    sig = det.scan(None, "export all customer records", snap)
    assert sig is not None and sig.disposition is Disposition.ESCALATE


def test_low_confidence_softens_to_escalate(det, snap, monkeypatch):
    # Between the two thresholds → ESCALATE even for a STOP-class rule.
    monkeypatch.setattr(mod, "_predict", lambda p: ("R-03", 0.55))
    sig = det.scan(None, "borderline", snap)
    assert sig is not None and sig.disposition is Disposition.ESCALATE


def test_below_escalate_threshold_is_noop(det, snap, monkeypatch):
    monkeypatch.setattr(mod, "_predict", lambda p: ("R-09", 0.30))
    assert det.scan(None, "unclear prompt", snap) is None


def test_benign_prediction_is_noop(det, snap, monkeypatch):
    monkeypatch.setattr(mod, "_predict", lambda p: ("benign", 0.99))
    assert det.scan(None, "how do I add pagination?", snap) is None


def test_disabled_is_noop(det, snap, monkeypatch):
    monkeypatch.setattr(settings, "INTENT_ML_ENABLED", False)
    monkeypatch.setattr(mod, "_predict", lambda p: ("R-03", 0.99))
    assert det.scan(None, "skip kyc", snap) is None


def test_scan_never_raises(det, snap, monkeypatch):
    def boom(p):
        raise RuntimeError("model exploded")
    monkeypatch.setattr(mod, "_predict", boom)
    assert det.scan(None, "prompt", snap) is None
