"""Contract tests for the PDP composition root."""

from __future__ import annotations

from app.pdp.decision import Disposition, Signal
from app.pdp.factory import build_pipeline, default_stages, detector_stage
from app.pdp.pipeline import Pipeline
from app.policy.store import PolicyStore

CTX = object()


def test_default_stages_empty_on_day1() -> None:
    assert default_stages() == []


def test_build_pipeline_returns_pipeline() -> None:
    assert isinstance(build_pipeline(PolicyStore()), Pipeline)


def test_detector_stage_passes_through_none() -> None:
    stage = detector_stage(lambda ctx, prompt, snap: None)
    assert stage(CTX, "hi", None) is None


def test_detector_stage_wraps_signal_into_decision() -> None:
    signal = Signal("injection", "R-06", Disposition.STOP, "prompt injection")
    stage = detector_stage(lambda ctx, prompt, snap: signal)
    decision = stage(CTX, "hi", None)
    assert decision.disposition is Disposition.STOP
    assert decision.reason == "prompt injection"
    assert decision.signals == (signal,)
