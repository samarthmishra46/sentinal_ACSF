# RYAN-DAY2
"""PEP enforcement — turn a Decision into a user-facing response.

Owner: Ryan.
Gate: Day-1 — apply() dispatches on the Decision's disposition to an action
handler (ALLOW / STOP / ESCALATE in V1) and returns the response body dict
{decision, reason, response}.

Day-2 (real actions):
  - STOP returns a plain-language, policy-cited refusal (rule_id + policy_id).
  - ESCALATE writes to the escalation queue (console now, Slack placeholder).
  - ALLOW now runs the OUTPUT PIPELINE on the assistant's answer before it
    leaves: a response that leaks PII/secrets, weakens compliance, ships exploit
    code, or shows the AI was steered off-role is BLOCKed (fail-safe) even though
    the pre-model gate passed. This is the post-model enforcement point.

Design notes:
  - Dispatch is by Disposition *member*. Samarth's locked enum has 3 members
    (ALLOW/ESCALATE/STOP); REDACT is a V2 outcome, so handle_redact is kept
    dormant (never dispatched today) and gets wired in when REDACT lands.
  - case _ is fail-closed: an unknown disposition is escalated to a human,
    never answered.
  - The STOP/ESCALATE cite comes from decision.decisive_signal (rule_id) — the
    Decision carries no policy_id; the audit logger resolves rule_id -> policy_id
    via app.policy.models.policy_for. Messages stay plain-language; no tracebacks.
"""
from app._compat import Decision, Disposition, RequestContext
from app.assistant.stub import StubAssistant
from app.escalation.queue import EscalationQueue
from app.pdp.output_scanner import OutputDisposition, OutputScanner, policy_id_for

# Module-level singletons — swap StubAssistant for the real client in V2 without
# touching the handlers below.
_assistant = StubAssistant()
_escalation = EscalationQueue()
_output_scanner = OutputScanner()


def apply(decision: Decision, prompt: str, ctx: RequestContext) -> tuple[dict, Decision]:
    """Dispatch a Decision to its action handler.

    Returns ``(response_body, effective_decision)``. The second item is the
    decision that was ACTUALLY enforced — which differs from the input ``decision``
    when the egress gate turns an ALLOW into a STOP. Ingress audits the effective
    decision so the log explains the real outcome (rule + signals), not a stale
    pre-model verdict.
    """
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


def handle_allow(
    decision: Decision, prompt: str, ctx: RequestContext
) -> tuple[dict, Decision]:
    """ALLOW: forward to the assistant, then scan the answer at the egress gate.

    The pre-model verdict was ALLOW, but the answer itself is still untrusted:
    run the output pipeline (O1->O4) and BLOCK it if it leaks. A clean answer is
    returned as-is; a blocked one is converted to a STOP so the user gets a
    policy-cited refusal and the audit log records the egress rule.
    """
    answer = _assistant.generate(prompt, ctx)
    verdict = _output_scanner.scan(answer, prompt, ctx)
    if verdict.disposition is OutputDisposition.PASS:
        return {"decision": "ALLOW", "reason": decision.reason, "response": answer}, decision

    # Egress leak. V1 is fail-safe: drop the answer and STOP. (REDACT — forward a
    # cleaned answer — is built in output_scanner.redact but dormant until V2.)
    out_decision = verdict.to_decision(policy_version=decision.policy_version)
    return handle_stop(out_decision, prompt, ctx, where="output")


def handle_stop(
    decision: Decision, prompt: str, ctx: RequestContext, where: str = "input"
) -> tuple[dict, Decision]:
    """STOP: block the request/response; return a policy-cited reason, no answer.

    ``where`` distinguishes a pre-model block ("input") from an egress block
    ("output") in the console log; the user-facing payload shape is identical.
    """
    message = _cited_refusal(decision, where)
    sig = decision.decisive_signal
    cite = sig.rule_id if sig and sig.rule_id else "policy"
    print(f"[STOP/{where}] Blocked under {cite}: {decision.reason}")
    return {"decision": "STOP", "reason": message, "response": None}, decision


def _cited_refusal(decision: Decision, where: str) -> str:
    """Compose a plain-language, policy-cited refusal for the user.

    Cites the rule_id (always on the decisive signal) and the mapped policy_id.
    No tracebacks, no internal detail beyond the policy reference.
    """
    sig = decision.decisive_signal
    rule_id = sig.rule_id if sig else None
    policy_id = policy_id_for(rule_id)
    cite = " / ".join(c for c in (policy_id, rule_id) if c)
    base = decision.reason or "This request was blocked by policy."
    if where == "output":
        base = f"The assistant's response was withheld: {base}."
    if cite:
        return f"{base} (blocked under {cite})"
    return base


def handle_escalate(
    decision: Decision, prompt: str, ctx: RequestContext
) -> tuple[dict, Decision]:
    """ESCALATE: queue for human review; tell the user it is under review."""
    _escalation.enqueue(prompt, ctx, decision)
    return {
        "decision": "ESCALATE",
        "reason": decision.reason,
        "response": "Your request is under review.",
    }, decision


def handle_redact(decision: Decision, prompt: str, ctx: RequestContext) -> dict:
    """REDACT (V2 — dormant): strip sensitive spans and forward the cleaned prompt.

    Not reachable in V1: Samarth's Disposition has no REDACT member, so the
    pipeline can never emit it and apply() never dispatches here. Kept ready for
    V2. Day-3+ work: strip flagged spans, annotate what was removed, forward.
    """
    print("[REDACT] Would strip spans, forward cleaned")
    return {"decision": "REDACT", "reason": decision.reason, "response": "<redacted stub answer>"}
