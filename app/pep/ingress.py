# RYAN-DAY2
"""PEP ingress — the request entry path: build context -> evaluate -> enforce.

Owner: Ryan.
Gate: Day-1 noon — handle_request is what the POST /v1/chat route calls.

Day-2 integration:
  - The stub ``pdp_evaluate`` is gone. Ingress now drives Samarth's REAL pipeline
    via its composition root: ``build_pipeline(store)`` is called ONCE at import
    (the PEP's startup), then ``pipeline.evaluate(ctx, prompt)`` runs per request
    (sync, per the locked contract). With no detectors registered yet the seeded
    baseline resolves to ALLOW ("no detector objected"); Sneha's/Nikhil's/
    Anamika's stages plug into ``default_stages()`` as they land — no change here.
  - An OUTER fail-closed guard wraps the whole path so a PEP-side error (context
    build, enforcement, audit) is converted to a safe ESCALATE response instead
    of a 500 with a traceback. The pipeline already fails closed internally; this
    guards the code on either side of it.
  - One audit record is emitted per request (see app.pep.audit_hook). Today that
    is a console sink; on integration it swaps for Nikhil's AsyncAuditLogger.

Identity (Anamika, integrated):
  - RequestContext is no longer hand-built here. It comes from the EIM mock
    (app/identity/eim_client.py::EIMClient.get_context(user_id)), which resolves
    role / tenant / owned_services / session_token for a known user. An UNKNOWN
    user is an authentication failure: the PEP fails closed (STOP) before the
    request ever reaches the PDP or the assistant.
"""
from time import perf_counter

from app._compat import Decision
from app.identity.eim_client import EIMClient
from app.monitoring import signals
from app.pdp.factory import build_pipeline
from app.pep import audit_hook, enforcement
from app.policy.store import PolicyStore

# --- PEP startup (composition root) ---------------------------------------- #
# Built once at import time, not per request. The PolicyStore starts with an
# empty snapshot; Adhiraj/Samarth's loader populates it from the bundle dir.
_store = PolicyStore()
_pipeline = build_pipeline(_store)
_audit = audit_hook.default_sink()
_eim = EIMClient()


def handle_request(prompt: str, user_id: str) -> dict:
    """Handle one chat request end-to-end; return the response body dict.

    Two fail-closed guards wrap the path:
      * an unknown/unauthenticated user is denied (STOP) before the PDP/AI;
      * anything else that escapes becomes a human-review ESCALATE — never a
        leaked traceback or an unscreened answer.
    """
    started = perf_counter()
    ctx = None
    try:
        # Identity first: resolve the caller. Fail closed on an unknown user.
        try:
            ctx = _eim.get_context(user_id)
        except ValueError as exc:
            print(f"[AUTH-DENY] {exc}")
            decision = Decision.stop(reason=f"unknown or unauthenticated user: {user_id}")
            response = {
                "decision": "STOP",
                "reason": "Your identity could not be verified for this request.",
                "response": None,
            }
        else:
            if not audit_hook.is_healthy():
                # Day-3 fail-closed: the audit trail is a compliance control —
                # if the backend is down, hold for a human rather than answer
                # un-audited. Routed through apply() so the escalation queue
                # (and its Slack notify) still fires.
                decision = Decision.escalate(
                    reason="audit backend unavailable — answer withheld pending review"
                )
            else:
                decision = _pipeline.evaluate(ctx, prompt)
            # apply() returns the EFFECTIVE decision — an egress block rewrites a
            # pre-model ALLOW into a STOP, and we must audit what was enforced.
            response, decision = enforcement.apply(decision, prompt, ctx)
    except Exception as exc:  # fail-closed: hold for a human, reveal nothing
        print(f"[PEP-ERROR] {type(exc).__name__}: {exc}")
        decision = Decision.escalate(reason="internal error — held for review")
        response = {
            "decision": "ESCALATE",
            "reason": "Your request could not be processed and is under review.",
            "response": None,
        }

    latency_ms = (perf_counter() - started) * 1000.0
    # Pass the active snapshot so the audit sink can resolve policy_triggered from
    # the shared catalog (policy_for) — same lookup the PDP uses.
    _audit.record(
        decision, response, prompt=prompt, ctx=ctx,
        latency_ms=latency_ms, snapshot=_store.active,
    )
    # Adhiraj's monitoring counters (threat/role/decision), one bump per request.
    sig = decision.decisive_signal
    signals.increment(
        sig.rule_id if sig and sig.rule_id else "none",
        ctx.role if ctx else "unknown",
        response["decision"],
    )
    return response
