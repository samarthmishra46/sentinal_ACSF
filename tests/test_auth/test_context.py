from datetime import datetime
from app.identity.context import RequestContext


def test_context_creation():
    ctx = RequestContext(
        user_id="u-test",
        role="Engineer",
        tenant="org-test",
        owned_services=["svc-a", "svc-b"],
        session_token="tok-test",
    )
    assert ctx.user_id == "u-test"
    assert ctx.role == "Engineer"
    assert ctx.tenant == "org-test"
    assert ctx.owned_services == ["svc-a", "svc-b"]
    assert ctx.session_token == "tok-test"


def test_timestamp_auto_set():
    ctx = RequestContext(
        user_id="u-x", role="Support", tenant="org-x",
        owned_services=[], session_token="tok-x",
    )
    assert isinstance(ctx.timestamp, datetime)


def test_empty_owned_services():
    ctx = RequestContext(
        user_id="u-support", role="Support", tenant="org-acme",
        owned_services=[], session_token="tok-s",
    )
    assert ctx.owned_services == []


def test_wildcard_owned_services():
    ctx = RequestContext(
        user_id="u-sec", role="SecurityReviewer", tenant="org-acme",
        owned_services=["*"], session_token="tok-sec",
    )
    assert "*" in ctx.owned_services


# ── Day 3: actor_type field ──────────────────────────────────

def test_actor_type_default_is_a01():
    # Backward-compatible default — existing tests that omit actor_type still work
    ctx = RequestContext(
        user_id="u-test", role="Engineer", tenant="org-acme",
        owned_services=[], session_token="tok-test",
    )
    assert ctx.actor_type == "A-01"


def test_actor_type_explicit():
    ctx = RequestContext(
        user_id="u-test", role="SecurityReviewer", tenant="org-acme",
        owned_services=["*"], session_token="tok-test",
        actor_type="A-03",
    )
    assert ctx.actor_type == "A-03"
