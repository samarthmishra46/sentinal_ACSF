# RYAN-DAY1
"""EscalationQueue — V1 console stub for the human-review escalation path.

Owner: Ryan.
Gate: Day-1 noon — the ESCALATE enforcement action enqueues here. For V1 this
logs a one-line JSON summary to stdout so it is greppable and easy to ship to
Slack later. The real reviewer payload (full request context) lands on Day 3.
"""
import json

from app._compat import Decision, RequestContext


class EscalationQueue:
    """Holds escalated requests for human review.

    V1: print a one-line JSON summary to the console.
    V2/Day-3: POST to Slack and/or persist to a real review queue.
    """

    def enqueue(self, prompt: str, ctx: RequestContext, decision: Decision) -> None:
        sig = decision.decisive_signal
        summary = {
            "event": "ESCALATION",
            "user_id": ctx.user_id,
            "role": ctx.role,
            "tenant": ctx.tenant,
            "rule_id": sig.rule_id if sig else None,
            "policy_version": decision.policy_version,
            "reason": decision.reason,
            "prompt_preview": prompt[:80],
        }
        print(json.dumps(summary))
        # TODO Day 3: POST to Slack webhook
