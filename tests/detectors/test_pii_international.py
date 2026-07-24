"""Tests for the international PII patterns added via tools/pii_gapfind.py."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.pdp.decision import Disposition
from app.pdp.detectors.pii import PIIDetector
from app.policy.models import Snapshot


@pytest.fixture
def pii() -> PIIDetector:
    return PIIDetector()


@pytest.fixture
def snap() -> Snapshot:
    return Snapshot(version="t", created_at=datetime.now(timezone.utc))


@pytest.fixture
def ctx():
    from app.identity.context import RequestContext
    return RequestContext(user_id="u", role="Engineer", tenant="firm-alpha",
                          owned_services=["svc"], session_token="t")


@pytest.mark.parametrize("prompt", [
    "the customer's Aadhaar 2345 6789 0123 needs verification",
    "IBAN GB33BUKB20201555555555 for the payout",
    "SWIFT code DEUTDEFF for the transfer",
    "their SSN 123-45-6789 is on file",
    "card 4111 1111 1111 1111 was declined",
    "email the report to jane.doe@example.com",
])
def test_international_pii_detected(pii, ctx, snap, prompt):
    sig = pii.scan(ctx, prompt, snap)
    assert sig is not None, f"missed PII in: {prompt}"
    assert sig.disposition is Disposition.STOP
    assert sig.rule_id == "R-01"


@pytest.mark.parametrize("prompt", [
    "the meeting is in room 4021 on level 3",          # bare number, not a card
    "our API returns 200 or 404 status codes",         # not SSN/PAN
    "the SWIFT protocol is unrelated to banking here",  # 'SWIFT' word, no code
    "increment the counter from 1234 to 5678",          # not grouped card
])
def test_no_false_positive_on_benign_numbers(pii, ctx, snap, prompt):
    assert pii.scan(ctx, prompt, snap) is None, f"false positive on: {prompt}"
