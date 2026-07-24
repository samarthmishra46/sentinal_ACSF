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


# Process-wide behaviour tracker — stateful, so it lives outside the stateless
# detector chain and is shared across requests (that is the whole point: it sees
# the pattern across a user's requests, which no single detector can).
_behaviour_tracker = None


def _get_behaviour_tracker():
    global _behaviour_tracker
    if _behaviour_tracker is None:
        from app.config import settings
        from app.pdp.behaviour import BehaviourTracker
        _behaviour_tracker = BehaviourTracker(
            max_queries_per_hour=settings.BEHAVIOUR_MAX_QUERIES_PER_HOUR,
            max_distinct_customers=settings.BEHAVIOUR_MAX_DISTINCT_CUSTOMERS,
            max_off_owned_per_hour=settings.BEHAVIOUR_MAX_OFF_OWNED_PER_HOUR,
            max_escalate_streak=settings.BEHAVIOUR_MAX_ESCALATE_STREAK,
        )
    return _behaviour_tracker


def behaviour_stage(ctx: "RequestContext", prompt: str, snap: Snapshot) -> Optional[Decision]:
    """Stage 10 — session-level anomaly. A bare stage (not a BaseDetector) because
    it is *stateful*: it records this request into a rolling per-user window and
    ESCALATEs when the pattern is abnormal. Never raises; disabled by default.
    """
    from app.config import settings
    if not settings.BEHAVIOUR_ENABLED:
        return None
    try:
        tracker = _get_behaviour_tracker()
        owned = list(getattr(ctx, "owned_services", []) or [])
        service = owned[0] if owned else None  # PEP passes the real target; default to own
        verdict = tracker.record_and_check(
            user_id=getattr(ctx, "user_id", "unknown"),
            prompt=prompt,
            owned_services=owned,
            service=service,
            now=getattr(ctx, "timestamp", None),
        )
        if not verdict.anomalous:
            return None
        signal = Signal(
            detector="behaviour_stage",
            rule_id="R-22",
            disposition=Disposition.ESCALATE,
            reason=f"Anomalous access pattern detected: {verdict.reason}.",
            metadata={"feature": verdict.feature, "value": verdict.value,
                      "threshold": verdict.threshold, "source": "behaviour"},
        )
        return Decision(Disposition.ESCALATE, signal.reason, (signal,))
    except Exception:  # a stateful stage must never take the pipeline down
        return None


def default_stages() -> list[Stage]:
    """The ordered pipeline stages: authorization, detectors 4→9, behaviour 10.

    Cheapest-first / fail-fast. Stage 3 is authorization (Anamika's engine);
    stages 4–9 are the detectors, wrapped by ``detector_stage``; stage 10 is the
    stateful behaviour stage (bare, outside ALL_DETECTORS). Imports are lazy so
    importing this module never drags the detector chain.
    """
    from app.pdp.detectors import ALL_DETECTORS  # lazy

    stages: list[Stage] = [_authz_stage]
    for det in sorted(ALL_DETECTORS, key=lambda d: d.stage_order):
        stage = detector_stage(det.scan)
        stage.__name__ = det.stage_name  # name by detector for audit/fail-closed messages
        stages.append(stage)
    stages.append(behaviour_stage)
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
