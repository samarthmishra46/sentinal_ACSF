# RYAN-DAY3
"""EscalationQueue — the human-review escalation path.

Owner: Ryan.
Gate: Day-1 noon — the ESCALATE enforcement action enqueues here.
Day-3: Slack notification. Each escalation still prints its one-line JSON
summary (greppable, and the V1 queue of record); if ``settings.SLACK_WEBHOOK``
is configured the same summary is POSTed to Slack for the reviewer. The webhook
call is strictly fail-safe: a Slack outage must never break, block, or 500 the
request path, so failures are logged and swallowed. Reviewer UI stays V2 —
Slack notification only in V1 (sprint plan scope).
"""
import json

import httpx

from app._compat import Decision, RequestContext
from app.config import settings

#: Keep the reviewer ping snappy; the request path should never hang on Slack.
_SLACK_TIMEOUT_S = 2.0


class EscalationQueue:
    """Holds escalated requests for human review.

    V1: one-line JSON summary to the console + Slack webhook notification.
    V2: persist to a real review queue with a reviewer UI.
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
        self._notify_slack(summary)

    def _notify_slack(self, summary: dict) -> None:
        """POST the request summary to the reviewer channel. Never raises."""
        webhook = settings.SLACK_WEBHOOK
        if not webhook:
            return  # not configured — the console line above is the V1 queue
        text = (
            f":rotating_light: *Sentinel escalation* — user `{summary['user_id']}` "
            f"({summary['role']}, {summary['tenant']})\n"
            f"> rule: `{summary['rule_id'] or 'n/a'}` · "
            f"policy bundle: `{summary['policy_version']}`\n"
            f"> reason: {summary['reason']}\n"
            f"> prompt: “{summary['prompt_preview']}…”"
        )
        try:
            resp = httpx.post(webhook, json={"text": text}, timeout=_SLACK_TIMEOUT_S)
            resp.raise_for_status()
        except Exception as exc:  # fail-safe: notification is best-effort
            print(f"[ESCALATION] Slack notify failed: {type(exc).__name__}: {exc}")
