"""Tests for the Stage-9 destructive-ops detector and the PAN PII extension.

Covers the coverage gap found in manual testing: destructive data operations
(delete/drop customer records) and Indian PAN as customer PII.
"""

from __future__ import annotations

import pytest

from app.pdp.decision import Disposition
from app.pdp.detectors.destructive_ops import DestructiveOpsDetector
from app.pdp.detectors.pii import PIIDetector
# eng / comp / snap fixtures come from tests/detectors/conftest.py (auto-discovered)


@pytest.fixture
def det() -> DestructiveOpsDetector:
    return DestructiveOpsDetector()


@pytest.fixture
def pii() -> PIIDetector:
    return PIIDetector()


# ── Destructive-ops detector ────────────────────────────────────────────────

@pytest.mark.parametrize("prompt", [
    "delete person on database for this PAN ABCDE1234F",
    "write a query to delete all customer records from the database",
    "DROP TABLE customers;",
    "truncate the kyc records table",
    "purge every user account from the db",
    "erase this client's profile permanently",
])
def test_destructive_op_escalates(det, eng, snap, prompt) -> None:
    sig = det.scan(eng, prompt, snap)
    assert sig is not None, f"expected a signal for: {prompt}"
    assert sig.disposition is Disposition.ESCALATE
    assert sig.rule_id == "R-21"
    assert sig.detector == "destructive_ops_scanner"


@pytest.mark.parametrize("prompt", [
    "how do I delete a temporary file in Python?",
    "remove this code comment before committing",
    "explain how the DELETE HTTP verb differs from PUT",
    "how do I write a retry loop with exponential backoff?",
])
def test_destructive_op_does_not_fire_on_benign(det, eng, snap, prompt) -> None:
    # A destructive verb with no customer/data object must NOT fire.
    assert det.scan(eng, prompt, snap) is None


def test_destructive_op_never_raises(det, eng, snap) -> None:
    # Defensive: odd input must not raise (BaseDetector contract).
    assert det.scan(eng, "", snap) is None


# ── PAN recognised as PII (R-01) ────────────────────────────────────────────

@pytest.mark.parametrize("prompt", [
    "customer PAN is ABCDE1234F",
    "the applicant's PAN ABCDE1234F needs verification",
    "abcde1234f",  # lower-case still matches
])
def test_pan_detected_as_pii(pii, eng, snap, prompt) -> None:
    sig = pii.scan(eng, prompt, snap)
    assert sig is not None, f"PAN not detected in: {prompt}"
    assert sig.disposition is Disposition.STOP
    assert sig.rule_id == "R-01"
    assert "PAN" in sig.metadata["matched_entity"]


@pytest.mark.parametrize("prompt", [
    "the meeting is at 10am in room A1234B",   # not a PAN structure
    "explain what a PAN card is",              # concept, no number
])
def test_pan_no_false_positive(pii, eng, snap, prompt) -> None:
    assert pii.scan(eng, prompt, snap) is None
