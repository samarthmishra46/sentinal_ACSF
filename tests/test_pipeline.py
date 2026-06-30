"""Contract tests for the evaluation pipeline."""

from __future__ import annotations

from app.pdp.decision import Decision, Disposition
from app.pdp.pipeline import Pipeline
from app.policy.store import PolicyStore


# Trivial stand-ins: the pipeline never inspects ctx, and stages here ignore
# the snapshot, so plain objects suffice (no real identity/policy needed).
CTX = object()


def _noop(ctx, prompt, snap):
    """A stage that never objects."""
    return None


def test_all_stages_pass_yields_allow() -> None:
    pipe = Pipeline(PolicyStore(), stages=[_noop, _noop])
    result = pipe.evaluate(CTX, "hello")
    assert result.disposition is Disposition.ALLOW
    assert result.reason == "no detector objected"


def test_stop_short_circuits_later_stages() -> None:
    ran: list[str] = []

    def stopper(ctx, prompt, snap):
        ran.append("stopper")
        return Decision.stop("blocked")

    def spy(ctx, prompt, snap):
        ran.append("spy")  # must never execute
        return None

    pipe = Pipeline(PolicyStore(), stages=[stopper, spy])
    result = pipe.evaluate(CTX, "hello")

    assert result.disposition is Disposition.STOP
    assert ran == ["stopper"]  # spy proven not to have run
