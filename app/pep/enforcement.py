# RYAN-DAY1
"""PEP enforcement — turn a Decision into a user-facing response.

Owner: Ryan.
Gate: Day-1 — apply() dispatches on the Decision's disposition to a stub action
handler (ALLOW / STOP / ESCALATE in V1) and returns the response body dict
{decision, reason, response}.

Design notes:
  - Dispatch is by Disposition *member*. Samarth's locked enum has 3 members
    (ALLOW/ESCALATE/STOP); REDACT is a V2 outcome, so handle_redact is kept
    dormant (never dispatched today) and gets wired in when REDACT lands.
  - case _ is fail-closed: an unknown disposition is escalated to a human,
    never answered.
  - The STOP/ESCALATE cite comes from decision.decisive_signal (rule_id) — the
    Decision carries no policy_id; the audit logger resolves rule_id -> policy_id
    via app.policy.models.policy_for. Messages stay plain-language; no tracebacks.
  - Real action logic (real STOP wording, Slack escalation) is Day-2/3 work.
"""
from app._compat import Decision, Disposition, RequestContext
from app.assistant.stub import StubAssistant
from app.escalation.queue import EscalationQueue

# Module-level singletons — swap StubAssistant for the real client in V2 without
# touching the handlers below.
_assistant = StubAssistant()
_escalation = EscalationQueue()


def apply(decision: Decision, prompt: str, ctx: RequestContext) -> dict:
    """Dispatch a Decision to its action handler and return the response dict."""
    match decision.disposition:
        case Disposition.ALLOW:
            return handle_allow(decision, prompt, ctx)
        case Disposition.ESCALATE:
            return handle_escalate(decision, prompt, ctx)
        case Disposition.STOP:
            return handle_stop(decision, prompt, ctx)
        case _:
            # Fail-closed: never let an unrecognised disposition reach the AI.
            # Mirrors the pipeline/combiner fallback -> ESCALATE.
            return handle_escalate(decision, prompt, ctx)


def handle_allow(decision: Decision, prompt: str, ctx: RequestContext) -> dict:
    """ALLOW: forward to the (stub) assistant and return its answer."""
    answer = _assistant.generate(prompt, ctx)
    return {"decision": "ALLOW", "reason": decision.reason, "response": answer}


def handle_stop(decision: Decision, prompt: str, ctx: RequestContext) -> dict:
    """STOP: block before the AI; return the rule-cited reason, no answer."""
    sig = decision.decisive_signal
    cite = sig.rule_id if sig and sig.rule_id else "policy"
    print(f"[STOP] Blocked under {cite}: {decision.reason}")
    return {"decision": "STOP", "reason": decision.reason, "response": None}


def handle_escalate(decision: Decision, prompt: str, ctx: RequestContext) -> dict:
    """ESCALATE: queue for human review; tell the user it is under review."""
    _escalation.enqueue(prompt, ctx, decision)
    return {
        "decision": "ESCALATE",
        "reason": decision.reason,
        "response": "Your request is under review.",
    }


def handle_redact(decision: Decision, prompt: str, ctx: RequestContext) -> dict:
    """REDACT (V2 — dormant): strip sensitive spans and forward the cleaned prompt.

    Not reachable in V1: Samarth's Disposition has no REDACT member, so the
    pipeline can never emit it and apply() never dispatches here. Kept ready for
    V2. Day-3+ work: strip flagged spans, annotate what was removed, forward.
    """
    print("[REDACT] Would strip spans, forward cleaned")
    return {"decision": "REDACT", "reason": decision.reason, "response": "<redacted stub answer>"}
