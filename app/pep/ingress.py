# RYAN-DAY1
"""PEP ingress — the request entry path: build context -> evaluate -> enforce.

Owner: Ryan.
Gate: Day-1 noon — handle_request is what the POST /v1/chat route calls. It
builds a stub RequestContext, asks the (stub) PDP for a Decision, and runs
enforcement, returning the dict that becomes the HTTP response body.

V1 stubs that teammates replace on integration:
  - RequestContext is hardcoded here; real values come from Anamika's EIM
    (app/identity/eim_client.py + app/identity/context.py).
  - pdp_evaluate is a local stub. On merge it is replaced by Samarth's pipeline
    via its composition root (app/pdp/factory.py): build the Pipeline once at
    startup, then call pipeline.evaluate(ctx, prompt). No auth/detection logic
    lives in this seat.
"""
from datetime import datetime, timezone

from app._compat import Decision, RequestContext
from app.pep import enforcement


def handle_request(prompt: str, user_id: str) -> dict:
    """Handle one chat request end-to-end; return the response body dict."""
    ctx = _build_stub_context(user_id)
    decision = pdp_evaluate(ctx, prompt)
    return enforcement.apply(decision, prompt, ctx)


def _build_stub_context(user_id: str) -> RequestContext:
    """Build a hardcoded RequestContext for V1.

    role and tenant are hardcoded per the Day-1 brief; owned_services,
    session_token, and timestamp are filled with simple stubs so the model
    shape is complete. All of this is replaced by the EIM lookup later.
    """
    return RequestContext(
        user_id=user_id,
        role="Engineer",                 # TODO: from EIM (Anamika) — hardcoded for Day-1
        tenant="AU-1",                   # TODO: from EIM (Anamika) — hardcoded for Day-1
        owned_services=[],               # TODO: from EIM (Anamika)
        session_token="stub-session",    # TODO: from EIM (Anamika)
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def pdp_evaluate(ctx: RequestContext, prompt: str) -> Decision:
    """STUB Policy Decision Point — always ALLOW for the Day-1 skeleton.

    On merge this is replaced by Samarth's pipeline composition root:
        from app.pdp.factory import build_pipeline
        # at startup:   pipeline = build_pipeline(store)
        # here:         return pipeline.evaluate(ctx, prompt)
    (note: the real pipeline's ALLOW reason is "no detector objected"). By design
    there is no authorization or detection logic in this seat.
    """
    # TODO: replace with app.pdp.factory.build_pipeline(store).evaluate(ctx, prompt).
    return Decision.allow(reason="stub: no PDP yet")
