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
    """GET /health returns 200 and {"status": "ok"}."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_chat_allow():
    """A benign prompt is ALLOWed and gets a non-null stub answer."""
    resp = client.post(
        "/v1/chat",
        json={"prompt": "Help me debug a function", "user_id": "ryan"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "ALLOW"
    assert body["response"] is not None
    assert "stub answer" in body["response"]


def test_chat_structure():
    """The response body has exactly the keys: decision, reason, response."""
    resp = client.post(
        "/v1/chat",
        json={"prompt": "anything", "user_id": "ryan"},
    )
    assert resp.status_code == 200
    assert set(resp.json().keys()) == {"decision", "reason", "response"}
