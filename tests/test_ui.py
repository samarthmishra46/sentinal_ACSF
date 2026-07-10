"""The minimal demo frontend is served at GET / (same-origin, no CORS).

Guards against the route silently breaking (e.g. the HTML file going missing)
without changing any /v1/chat behaviour.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_index_served() -> None:
    """GET / returns the HTML page."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    # A couple of anchors that must be present for the page to work.
    assert "/v1/chat" in resp.text
    assert 'id="prompt"' in resp.text


def test_index_offers_all_seeded_personas() -> None:
    """The persona dropdown covers the 5 seeded users + the unknown-user demo."""
    body = client.get("/").text
    for user_id in ("u-001", "u-002", "u-003", "u-004", "u-005", "u-999"):
        assert user_id in body, f"persona {user_id} missing from the UI"
