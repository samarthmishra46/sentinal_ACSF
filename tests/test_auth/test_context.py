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
