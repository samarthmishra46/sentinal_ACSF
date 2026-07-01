from app.pdp.authz.rbac import (
    has_capability,
    CODE_HELP, DOC, ARCH, REVIEW_SEC, REVIEW_COMP,
)


# Engineer checks
def test_engineer_can_code_help():
    assert has_capability("Engineer", CODE_HELP) is True

def test_engineer_can_doc():
    assert has_capability("Engineer", DOC) is True

def test_engineer_can_arch():
    assert has_capability("Engineer", ARCH) is True

def test_engineer_cannot_review_sec():
    assert has_capability("Engineer", REVIEW_SEC) is False

def test_engineer_cannot_review_comp():
    assert has_capability("Engineer", REVIEW_COMP) is False


# Support checks
def test_support_can_doc():
    assert has_capability("Support", DOC) is True

def test_support_cannot_code_help():
    assert has_capability("Support", CODE_HELP) is False

def test_support_cannot_arch():
    assert has_capability("Support", ARCH) is False


# SecurityReviewer checks
def test_security_reviewer_can_review_sec():
    assert has_capability("SecurityReviewer", REVIEW_SEC) is True

def test_security_reviewer_can_code_help():
    assert has_capability("SecurityReviewer", CODE_HELP) is True

def test_security_reviewer_cannot_review_comp():
    assert has_capability("SecurityReviewer", REVIEW_COMP) is False


# ComplianceOfficer checks
def test_compliance_officer_can_review_comp():
    assert has_capability("ComplianceOfficer", REVIEW_COMP) is True

def test_compliance_officer_can_doc():
    assert has_capability("ComplianceOfficer", DOC) is True

def test_compliance_officer_cannot_code_help():
    assert has_capability("ComplianceOfficer", CODE_HELP) is False


# Unknown role
def test_unknown_role_has_no_capabilities():
    for cap in [CODE_HELP, DOC, ARCH, REVIEW_SEC, REVIEW_COMP]:
        assert has_capability("Hacker", cap) is False
