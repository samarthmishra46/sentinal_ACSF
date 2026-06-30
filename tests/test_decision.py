"""Contract tests for Decision: decisive_signal and policy_version."""

from __future__ import annotations

from app.pdp.decision import Decision, Disposition, Signal


def test_policy_version_defaults_empty() -> None:
    assert Decision.allow("ok").policy_version == ""


def test_decisive_signal_none_when_no_signals() -> None:
    assert Decision.allow("ok").decisive_signal is None


def test_decisive_signal_picks_strictest() -> None:
    weak = Signal("pii", "R-01", Disposition.ALLOW, "clean")
    strong = Signal("injection", "R-06", Disposition.STOP, "prompt injection")
    decision = Decision.stop("blocked", signals=(weak, strong))
    assert decision.decisive_signal is strong
    assert decision.decisive_signal.rule_id == "R-06"
