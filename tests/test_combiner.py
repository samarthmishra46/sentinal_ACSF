"""Contract tests for the verdict combiner."""

from __future__ import annotations

from app.pdp.combiner import combine
from app.pdp.decision import Decision, Disposition, Signal


def test_empty_verdicts_fail_closed_to_escalate() -> None:
    result = combine([])
    assert result.disposition is Disposition.ESCALATE
    assert result.reason == "fail-closed: no verdicts produced"


def test_all_allow_yields_allow() -> None:
    result = combine([Decision.allow("a"), Decision.allow("b"), Decision.allow("c")])
    assert result.disposition is Disposition.ALLOW


def test_allow_and_stop_yields_stop() -> None:
    result = combine([Decision.allow("ok"), Decision.stop("blocked")])
    assert result.disposition is Disposition.STOP
    assert result.reason == "blocked"  # winning verdict supplies the reason


def test_allow_and_escalate_yields_escalate() -> None:
    result = combine([Decision.allow("ok"), Decision.escalate("review")])
    assert result.disposition is Disposition.ESCALATE
    assert result.reason == "review"


def test_signals_aggregated_from_all_verdicts() -> None:
    s1 = Signal("pii", "R-01", Disposition.ALLOW, "no pii")
    s2 = Signal("injection", "R-02", Disposition.STOP, "prompt injection")
    result = combine(
        [
            Decision.allow("ok", signals=(s1,)),
            Decision.stop("blocked", signals=(s2,)),
        ]
    )
    assert result.signals == (s1, s2)
