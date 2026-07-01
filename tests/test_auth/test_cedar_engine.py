from app.identity.context import RequestContext
from app.pdp.authz.cedar_engine import evaluate


def _ctx(role: str) -> RequestContext:
    return RequestContext(
        user_id="u-test",
        role=role,
        tenant="org-acme",
        owned_services=["svc-a"],
        session_token="tok-test",
    )


def test_engineer_is_allowed():
    assert evaluate(_ctx("Engineer")) == "ALLOW"


def test_support_is_allowed():
    assert evaluate(_ctx("Support")) == "ALLOW"


def test_security_reviewer_is_allowed():
    assert evaluate(_ctx("SecurityReviewer")) == "ALLOW"


def test_compliance_officer_is_allowed():
    assert evaluate(_ctx("ComplianceOfficer")) == "ALLOW"


def test_unknown_role_is_stopped():
    assert evaluate(_ctx("Hacker")) == "STOP"


def test_empty_role_is_stopped():
    assert evaluate(_ctx("")) == "STOP"


def test_action_parameter_accepted():
    # stub ignores action today; real Cedar will use it on Day 2
    assert evaluate(_ctx("Engineer"), action="code_review") == "ALLOW"
