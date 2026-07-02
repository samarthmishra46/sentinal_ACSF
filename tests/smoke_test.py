# RYAN-DAY1
"""Smoke test — the Day-1 noon gate for the Sentinel PEP.

Owner: Ryan.
Gate: Day-1 noon — proves the full round-trip works with stub logic:
POST /v1/chat -> ingress -> stub PDP (ALLOW) -> enforcement -> stub assistant.
Run with: pytest tests/
"""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    """GET /health returns 200, ok status, and the audit backend health."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "audit": "ok"}


def test_chat_allow():
    """A benign prompt from a KNOWN user (EIM u-001) is ALLOWed with an answer."""
    resp = client.post(
        "/v1/chat",
        json={"prompt": "Help me debug a function", "user_id": "u-001"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "ALLOW"
    assert body["response"] is not None
    assert "stub answer" in body["response"]
    # role comes from Anamika's EIM, not a hardcoded stub, now.
    assert "role=Engineer" in body["response"]


def test_chat_structure():
    """The response body has exactly the keys: decision, reason, response."""
    resp = client.post(
        "/v1/chat",
        json={"prompt": "anything", "user_id": "u-001"},
    )
    assert resp.status_code == 200
    assert set(resp.json().keys()) == {"decision", "reason", "response"}


def test_chat_unknown_user_is_denied():
    """An unknown user_id fails closed at the identity gate (STOP, no answer)."""
    resp = client.post(
        "/v1/chat",
        json={"prompt": "Help me debug a function", "user_id": "nobody"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "STOP"
    assert body["response"] is None


def test_monitoring_counter_bumps_per_request():
    """Every request increments Adhiraj's threat:role:decision counter (Day 3)."""
    from app.monitoring import signals

    before = signals.get_counts().get("none:Engineer:ALLOW", {}).get("count", 0)
    resp = client.post(
        "/v1/chat",
        json={"prompt": "Help me debug a function", "user_id": "u-001"},
    )
    assert resp.status_code == 200 and resp.json()["decision"] == "ALLOW"
    after = signals.get_counts()["none:Engineer:ALLOW"]["count"]
    assert after == before + 1
