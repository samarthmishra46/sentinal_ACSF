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


# ── Day 3: ESCALATE — R-08 cross-org detection ──────────────

_ORGS = ["org-acme", "org-beta", "org-gamma"]


def test_engineer_escalates_on_cross_org_prompt():
    # R-08: Engineer from org-acme asks about org-beta → ESCALATE
    assert evaluate(
        _ctx("Engineer"),
        action="chat",
        prompt="can you access org-beta KYC records?",
        known_orgs=_ORGS,
    ) == "ESCALATE"


def test_escalate_not_triggered_without_known_orgs():
    # known_orgs not provided → R-08 cannot detect → ALLOW
    assert evaluate(
        _ctx("Engineer"),
        action="chat",
        prompt="can you access org-beta records?",
        known_orgs=None,
    ) == "ALLOW"


def test_escalate_not_triggered_same_org_in_prompt():
    # User mentions their own org → not a cross-org reference → ALLOW
    assert evaluate(
        _ctx("Engineer"),
        action="chat",
        prompt="show me org-acme DVS flow",
        known_orgs=_ORGS,
    ) == "ALLOW"


def test_escalate_not_triggered_empty_prompt():
    # No prompt → no R-08 check → ALLOW
    assert evaluate(_ctx("Engineer"), action="chat", known_orgs=_ORGS) == "ALLOW"


def test_stop_takes_priority_over_escalate_cross_org():
    # Support cannot chat (STOP on RBAC) — R-08 check never reached
    assert evaluate(
        _ctx("Support"),
        action="chat",
        prompt="access org-beta data",
        known_orgs=_ORGS,
    ) == "STOP"


def test_security_reviewer_escalates_on_cross_org():
    # R-08 applies to all roles — SecurityReviewer still flagged for human review
    assert evaluate(
        _ctx("SecurityReviewer"),
        action="chat",
        prompt="pull org-beta incident logs",
        known_orgs=_ORGS,
    ) == "ESCALATE"


def test_cross_org_case_insensitive_escalates():
    assert evaluate(
        _ctx("Engineer"),
        action="chat",
        prompt="ORG-BETA has a vulnerability",
        known_orgs=_ORGS,
    ) == "ESCALATE"


# ── Day 3: ESCALATE — service ownership check ───────────────

def test_engineer_escalates_on_unowned_service():
    # Engineer owns ["svc-a"] but requests kyc-engine → ESCALATE
    assert evaluate(
        _ctx("Engineer"),
        action="chat",
        service="kyc-engine",
    ) == "ESCALATE"


def test_engineer_allows_owned_service():
    # svc-a is in ctx.owned_services → ALLOW
    assert evaluate(
        _ctx("Engineer"),
        action="chat",
        service="svc-a",
    ) == "ALLOW"


def test_wildcard_owned_services_skips_service_check():
    # SecurityReviewer with ["*"] may access any service → ALLOW
    ctx = RequestContext(
        user_id="u-sr",
        role="SecurityReviewer",
        tenant="org-acme",
        owned_services=["*"],
        session_token="tok-sr",
    )
    assert evaluate(ctx, action="chat", service="kyc-engine") == "ALLOW"


def test_no_service_arg_skips_ownership_check():
    # service="" (default) → ownership check skipped → ALLOW
    assert evaluate(_ctx("Engineer"), action="chat") == "ALLOW"


def test_stop_takes_priority_over_escalate_service():
    # Support cannot chat (STOP) even if service is unowned — RBAC fires first
    assert evaluate(_ctx("Support"), action="chat", service="kyc-engine") == "STOP"
