# RYAN-DAY1
"""StubAssistant — V1 stand-in for the BACK assistant (AI).

Owner: Ryan.
Gate: Day-1 noon — returns a deterministic canned answer so the full request
round-trip (ingress -> PDP -> enforcement -> response) works without a real model.
"""
from app._compat import RequestContext


# Structurally implements AssistantClient (see app/assistant/client.py):
# it provides `generate(prompt, ctx) -> str`, which is all the Protocol requires.
class StubAssistant:
    """V1 stub. V2 swap: real model behind same interface."""

    def generate(self, prompt: str, ctx: RequestContext) -> str:
        return f"[stub answer for role={ctx.role}] {prompt[:80]}"
