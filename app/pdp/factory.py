"""Composition root for the PDP pipeline.

Ryan's PEP calls ``build_pipeline(store)`` once at startup, stashes the returned
``Pipeline``, and calls ``.evaluate(ctx, prompt)`` per request. Stage *ordering*
is owned here (core engine), not in ingress.

Stays decoupled: imports no detector/identity module at runtime, so import order
can never block the team. Real stages get plugged into ``default_stages()`` on
Day 2 as detectors land.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Callable, Optional

from app.pdp.decision import Decision, Signal
from app.pdp.pipeline import Pipeline, Stage
from app.policy.models import Snapshot
from app.policy.store import PolicyStore

if TYPE_CHECKING:
    from app.identity.context import RequestContext

# A detector (Sneha's BaseDetector.scan) returns one Signal or None — a narrower
# shape than a Stage, which returns a full Decision. Referenced structurally only.
Detector = Callable[["RequestContext", str, Snapshot], Optional[Signal]]


def default_stages() -> list[Stage]:
    """The ordered stages for the standard pipeline.

    Empty today (Day 1 plumbing). Detectors and auth stages get appended here,
    cheapest-first / fail-fast, as they land on Day 2.
    """
    return []


def build_pipeline(store: PolicyStore, stages: Sequence[Stage] | None = None) -> Pipeline:
    """Build a ready-to-use ``Pipeline``. The single entry point for the PEP."""
    return Pipeline(store, default_stages() if stages is None else stages)


def detector_stage(detector: Detector) -> Stage:
    """Adapt a Signal-returning detector into a Decision-returning Stage.

    Bridges Sneha's ``BaseDetector.scan(ctx, prompt, snap) -> Signal | None`` to
    the pipeline's ``Stage`` contract: ``None`` stays ``None`` (no objection);
    otherwise the signal's disposition becomes the stage's Decision and the
    signal rides along as evidence.
    """

    def stage(ctx: "RequestContext", prompt: str, snap: Snapshot) -> Optional[Decision]:
        signal = detector(ctx, prompt, snap)
        if signal is None:
            return None
        return Decision(signal.disposition, signal.reason, (signal,))

    stage.__name__ = getattr(detector, "__name__", "detector_stage")
    return stage
