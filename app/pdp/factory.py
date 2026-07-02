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

from app.pdp.decision import Decision, Disposition, Signal
from app.pdp.pipeline import Pipeline, Stage
from app.policy.models import Snapshot
from app.policy.store import PolicyStore

if TYPE_CHECKING:
    from app.identity.context import RequestContext

# A detector (Sneha's BaseDetector.scan) returns one Signal or None — a narrower
# shape than a Stage, which returns a full Decision. Referenced structurally only.
Detector = Callable[["RequestContext", str, Snapshot], Optional[Signal]]


def _authz_stage(ctx: "RequestContext", prompt: str, snap: Snapshot) -> Optional[Decision]:
    """Stage 3 — authorization. Reuses Anamika's Cedar/RBAC ``evaluate()``.

    Her ``evaluate(ctx, action)`` returns a disposition string ("ALLOW"/"STOP");
    ALLOW means no objection (return None). Anything else becomes a Decision with
    an ``authz`` Signal. An unrecognised result fails closed to ESCALATE.
    """
    from app.pdp.authz.cedar_engine import (  # lazy import
        evaluate as cedar_evaluate,
        get_default_action,
    )

    # Use the role-appropriate default action (Anamika's Day-4 helper) instead of a
    # hardcoded "chat", so non-code roles (ComplianceOfficer/Support) aren't STOP'd
    # at Stage 3 for legitimate requests. Cross-org (R-08) stays in the detector
    # layer, so authz denials here are pure authorization (rule_id R-AUTH).
    result = cedar_evaluate(ctx, action=get_default_action(ctx))
    if result == "ALLOW":
        return None
    disposition = Disposition.__members__.get(result, Disposition.ESCALATE)
    reason = f"Authorization denied: role '{getattr(ctx, 'role', '?')}' is not permitted."
    signal = Signal(
        detector="authz",
        rule_id="R-AUTH",
        disposition=disposition,
        reason=reason,
        metadata={"engine_result": result},
    )
    return Decision(disposition, reason, (signal,))


def default_stages() -> list[Stage]:
    """The ordered pipeline stages: authorization first, then detectors 4→7.

    Cheapest-first / fail-fast. Stage 3 is authorization (Anamika's engine);
    stages 4–7 are Sneha's + Nikhil's detectors, wrapped by ``detector_stage``.
    Imports are lazy so importing this module never drags the detector chain.
    """
    from app.pdp.detectors import ALL_DETECTORS  # lazy

    stages: list[Stage] = [_authz_stage]
    for det in sorted(ALL_DETECTORS, key=lambda d: d.stage_order):
        stage = detector_stage(det.scan)
        stage.__name__ = det.stage_name  # name by detector for audit/fail-closed messages
        stages.append(stage)
    return stages


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
