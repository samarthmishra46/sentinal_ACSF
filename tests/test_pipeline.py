"""Contract tests for the evaluation pipeline."""

from __future__ import annotations

from datetime import datetime, timezone

from app.pdp.decision import Decision, Disposition
from app.pdp.pipeline import Pipeline
from app.policy.models import Snapshot
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


def test_raising_stage_fails_closed_to_escalate() -> None:
    ran: list[str] = []

    def boom(ctx, prompt, snap):
        raise RuntimeError("detector crashed")

    def later(ctx, prompt, snap):
        ran.append("later")  # exceptions don't short-circuit, so this must run
        return None

    pipe = Pipeline(PolicyStore(), stages=[boom, later])
    result = pipe.evaluate(CTX, "hello")  # must NOT raise

    assert result.disposition is Disposition.ESCALATE
    assert ran == ["later"]
    assert result.decisive_signal is not None
    assert result.decisive_signal.detector == "pipeline"
    assert "boom" in result.reason


def test_policy_version_stamped_from_snapshot() -> None:
    snap = Snapshot(version="v1.0", created_at=datetime.now(timezone.utc))
    pipe = Pipeline(PolicyStore(snap), stages=[_noop])
    result = pipe.evaluate(CTX, "hello")
    assert result.policy_version == "v1.0"
