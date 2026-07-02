"""Shared fixtures for Sneha's detector tests.

NO stubs. All modules are real and committed on develop.
pytest loads this before collecting tests in tests/detectors/.

File: tests/detectors/conftest.py
Owner: Sneha
"""

from __future__ import annotations

import pytest

from app.pdp.decision import Disposition, Signal
from app.identity.context import RequestContext
from app.policy.models import Snapshot


@pytest.fixture
def eng() -> RequestContext:
    """RequestContext for an engineer."""
    return RequestContext(
        user_id="eng-042",
        role="Engineer",
        tenant="firm-alpha",
        owned_services=["dvs-service"],
        session_token="tok-test",
    )


@pytest.fixture
def comp() -> RequestContext:
    """RequestContext for a compliance officer."""
    return RequestContext(
        user_id="comp-007",
        role="ComplianceOfficer",
        tenant="firm-alpha",
        owned_services=["*"],
        session_token="tok-test",
    )


@pytest.fixture
def snap() -> Snapshot:
    """Empty policy snapshot."""
    return Snapshot.empty()