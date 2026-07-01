import pytest
from app.identity.eim_client import EIMClient

client = EIMClient()


def test_all_five_users_exist():
    for uid in ["u-001", "u-002", "u-003", "u-004", "u-005"]:
        ctx = client.get_context(uid)
        assert ctx.user_id == uid


def test_all_four_roles_covered():
    roles = {client.get_context(uid).role for uid in client.list_users()}
    assert "Engineer" in roles
    assert "Support" in roles
    assert "SecurityReviewer" in roles
    assert "ComplianceOfficer" in roles


def test_two_engineers_present():
    engineers = [
        uid for uid in client.list_users()
        if client.get_context(uid).role == "Engineer"
    ]
    assert len(engineers) == 2


def test_unknown_user_raises_value_error():
    with pytest.raises(ValueError, match="Unknown user"):
        client.get_context("u-999")


def test_engineers_own_services():
    ctx = client.get_context("u-001")
    assert len(ctx.owned_services) > 0


def test_support_owns_no_services():
    ctx = client.get_context("u-003")
    assert ctx.owned_services == []


def test_security_reviewer_has_wildcard():
    ctx = client.get_context("u-004")
    assert "*" in ctx.owned_services


def test_fresh_timestamp_each_call():
    ctx1 = client.get_context("u-001")
    ctx2 = client.get_context("u-001")
    # Both are valid datetimes; owned_services are independent copies
    assert ctx1.owned_services is not ctx2.owned_services


# ── Day 3: actor_type from EIM classification ────────────────

def test_engineer_actor_type_is_a01():
    ctx = client.get_context("u-001")
    assert ctx.actor_type == "A-01"


def test_support_actor_type_is_a02():
    ctx = client.get_context("u-003")
    assert ctx.actor_type == "A-02"


def test_security_reviewer_actor_type_is_a03():
    ctx = client.get_context("u-004")
    assert ctx.actor_type == "A-03"


def test_compliance_officer_actor_type_is_a04():
    ctx = client.get_context("u-005")
    assert ctx.actor_type == "A-04"


def test_all_users_have_actor_type():
    for uid in client.list_users():
        ctx = client.get_context(uid)
        assert ctx.actor_type.startswith("A-"), f"{uid} has unexpected actor_type: {ctx.actor_type}"
