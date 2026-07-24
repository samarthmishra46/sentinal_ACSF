"""Cascade tests for MLInjectionDetector — kNN tier + classifier tier.

All monkeypatched: no embedding model, no attack bank, no torch. Exercises the
three-branch cascade logic in isolation so it runs in plain CI.
"""

from __future__ import annotations

import pytest

from app.config import settings
from app.pdp.decision import Disposition
from app.pdp.detectors import injection_ml as mod
from app.pdp.detectors.injection_ml import MLInjectionDetector
from app.pdp.knn.bank import BankEntry


@pytest.fixture
def det() -> MLInjectionDetector:
    return MLInjectionDetector()


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    # Default: kNN on, classifier off, thresholds at shipped values.
    monkeypatch.setattr(settings, "KNN_ENABLED", True)
    monkeypatch.setattr(settings, "ML_DETECTOR_ENABLED", False)
    monkeypatch.setattr(settings, "KNN_STOP_THRESHOLD", 0.80)
    monkeypatch.setattr(settings, "KNN_BAND_LOW", 0.72)
    yield


def _fake_nearest(sim: float, rule: str = "R-03", id_: str = "M-R03-01"):
    entry = BankEntry(id=id_, text="x", rule_id=rule, source="corpus")
    return lambda prompt: (sim, entry)


def test_high_similarity_stops_and_cites_matched_rule(det, monkeypatch):
    monkeypatch.setattr(mod, "_nearest_attack", _fake_nearest(0.94, "R-03"))
    sig = det.scan(None, "some paraphrased bypass", None)
    assert sig is not None
    assert sig.disposition is Disposition.STOP
    assert sig.rule_id == "R-03"                      # inherits the matched attack's rule
    assert sig.metadata["source"] == "knn"
    assert sig.metadata["nearest_id"] == "M-R03-01"
    assert sig.metadata["similarity"] == pytest.approx(0.94)


def test_far_below_band_no_objection(det, monkeypatch):
    monkeypatch.setattr(mod, "_nearest_attack", _fake_nearest(0.30))
    assert det.scan(None, "totally benign question", None) is None


def test_band_without_classifier_escalates(det, monkeypatch):
    # In the ambiguous band with the classifier off, kNN escalates as fallback.
    monkeypatch.setattr(mod, "_nearest_attack", _fake_nearest(0.75, "R-05"))
    sig = det.scan(None, "ambiguous prompt", None)
    assert sig is not None
    assert sig.disposition is Disposition.ESCALATE
    assert sig.rule_id == "R-05"
    assert sig.metadata["source"] == "knn"


def test_band_with_classifier_defers_to_it(det, monkeypatch):
    # Band + classifier on: the classifier is authoritative. Here it clears (None)
    # a benign near-miss, so the kNN band-escalate is correctly overridden.
    monkeypatch.setattr(settings, "ML_DETECTOR_ENABLED", True)
    monkeypatch.setattr(mod, "_nearest_attack", _fake_nearest(0.75))
    monkeypatch.setattr(mod, "_injection_score", lambda p: 0.05)  # classifier: clean
    assert det.scan(None, "benign near-miss in the band", None) is None


def test_band_with_classifier_can_stop(det, monkeypatch):
    monkeypatch.setattr(settings, "ML_DETECTOR_ENABLED", True)
    monkeypatch.setattr(mod, "_nearest_attack", _fake_nearest(0.75))
    monkeypatch.setattr(mod, "_injection_score", lambda p: 0.97)  # classifier: injection
    sig = det.scan(None, "real injection in the band", None)
    assert sig is not None and sig.disposition is Disposition.STOP
    assert sig.metadata["source"] == "ml"            # classifier decided


def test_knn_disabled_falls_back_to_classifier_only(det, monkeypatch):
    monkeypatch.setattr(settings, "KNN_ENABLED", False)
    monkeypatch.setattr(settings, "ML_DETECTOR_ENABLED", True)
    monkeypatch.setattr(mod, "_injection_score", lambda p: 0.95)
    sig = det.scan(None, "injection", None)
    assert sig is not None and sig.disposition is Disposition.STOP
    assert sig.metadata["source"] == "ml"


def test_both_disabled_is_noop(det, monkeypatch):
    monkeypatch.setattr(settings, "KNN_ENABLED", False)
    monkeypatch.setattr(settings, "ML_DETECTOR_ENABLED", False)
    assert det.scan(None, "anything", None) is None


def test_escalate_rule_ceiling_caps_stop(det, monkeypatch):
    # A high-similarity match to an ESCALATE-class rule (R-05 bulk extraction)
    # must ESCALATE, never STOP — similarity says "this is that attack", the
    # catalog says how strict that attack is.
    from datetime import datetime, timezone
    from app.policy.models import Snapshot
    snap = Snapshot(version="t", created_at=datetime.now(timezone.utc),
                    catalog={"R-05": {"id": "R-05", "disposition": "ESCALATE"}})
    monkeypatch.setattr(mod, "_nearest_attack", _fake_nearest(0.99, "R-05", "M-R05-01"))
    sig = det.scan(None, "exact known bulk-extraction attack", snap)
    assert sig is not None
    assert sig.disposition is Disposition.ESCALATE      # capped, not STOP
    assert sig.rule_id == "R-05"


def test_stop_rule_still_stops_with_snapshot(det, monkeypatch):
    from datetime import datetime, timezone
    from app.policy.models import Snapshot
    snap = Snapshot(version="t", created_at=datetime.now(timezone.utc),
                    catalog={"R-06": {"id": "R-06", "disposition": "STOP"}})
    monkeypatch.setattr(mod, "_nearest_attack", _fake_nearest(0.99, "R-06", "RT-05"))
    sig = det.scan(None, "exact known injection", snap)
    assert sig is not None and sig.disposition is Disposition.STOP


def test_scan_never_raises(det, monkeypatch):
    def boom(prompt):
        raise RuntimeError("bank exploded")
    monkeypatch.setattr(mod, "_nearest_attack", boom)
    assert det.scan(None, "prompt", None) is None     # swallowed per contract
