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


# ── Day 1 stub tests (still valid) ──────────────────────────

def test_unknown_role_is_stopped():
    assert evaluate(_ctx("Hacker")) == "STOP"

def test_empty_role_is_stopped():
    assert evaluate(_ctx("")) == "STOP"


# ── Day 2 real rule tests — action-based RBAC ───────────────

# Engineer
def test_engineer_can_chat():
    assert evaluate(_ctx("Engineer"), action="chat") == "ALLOW"

def test_engineer_can_code_review():
    assert evaluate(_ctx("Engineer"), action="code_review") == "ALLOW"

def test_engineer_can_view_arch():
    assert evaluate(_ctx("Engineer"), action="arch_view") == "ALLOW"

def test_engineer_can_access_docs():
    assert evaluate(_ctx("Engineer"), action="doc_access") == "ALLOW"

def test_engineer_cannot_security_review():
    # Engineers don't have REVIEW_SEC capability
    assert evaluate(_ctx("Engineer"), action="security_review") == "STOP"

def test_engineer_cannot_compliance_review():
    # Engineers don't have REVIEW_COMP capability
    assert evaluate(_ctx("Engineer"), action="compliance_review") == "STOP"


# Support
def test_support_cannot_chat():
    # Support only has DOC — chat requires CODE_HELP → STOP
    # Day 1 stub returned ALLOW for any known role; Day 2 real rules block this
    assert evaluate(_ctx("Support"), action="chat") == "STOP"

def test_support_cannot_code_review():
    assert evaluate(_ctx("Support"), action="code_review") == "STOP"

def test_support_can_access_docs():
    assert evaluate(_ctx("Support"), action="doc_access") == "ALLOW"

def test_support_cannot_security_review():
    assert evaluate(_ctx("Support"), action="security_review") == "STOP"


# SecurityReviewer
def test_security_reviewer_can_chat():
    assert evaluate(_ctx("SecurityReviewer"), action="chat") == "ALLOW"

def test_security_reviewer_can_security_review():
    assert evaluate(_ctx("SecurityReviewer"), action="security_review") == "ALLOW"

def test_security_reviewer_cannot_compliance_review():
    assert evaluate(_ctx("SecurityReviewer"), action="compliance_review") == "STOP"


# ComplianceOfficer
def test_compliance_officer_can_compliance_review():
    assert evaluate(_ctx("ComplianceOfficer"), action="compliance_review") == "ALLOW"

def test_compliance_officer_can_access_docs():
    assert evaluate(_ctx("ComplianceOfficer"), action="doc_access") == "ALLOW"

def test_compliance_officer_cannot_chat():
    # ComplianceOfficer only has DOC + REVIEW_COMP — chat requires CODE_HELP
    assert evaluate(_ctx("ComplianceOfficer"), action="chat") == "STOP"

def test_compliance_officer_cannot_code_review():
    assert evaluate(_ctx("ComplianceOfficer"), action="code_review") == "STOP"


# Default action fallback
def test_default_action_is_chat():
    # No action arg → defaults to "chat" → requires CODE_HELP
    assert evaluate(_ctx("Engineer")) == "ALLOW"
    assert evaluate(_ctx("Support")) == "STOP"
