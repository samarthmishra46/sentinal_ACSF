"""Shared stubs and fixtures for Sentinel tests.

pytest loads this file automatically before collecting any test module.
It stubs out the dependency modules that other team members own
(decision, context, models) so Sneha's detector imports resolve
without needing the full app stack running.

File: tests/conftest.py
Owner: Sneha
"""

from __future__ import annotations

import os
import sys
import types
from dataclasses import dataclass, field
from enum import IntEnum
from unittest.mock import MagicMock

import pytest

# ── Ensure project root is in sys.path ──────────────────────────────────

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ── Stub types matching Samarth's committed decision.py ─────────────────


class Disposition(IntEnum):
    ALLOW = 0
    ESCALATE = 1
    STOP = 2


@dataclass(frozen=True)
class Signal:
    detector: str
    rule_id: str | None
    disposition: Disposition
    reason: str
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)


@dataclass
class RequestContext:
    user_id: str = "eng-042"
    role: str = "Engineer"
    tenant: str = "firm-alpha"
    owned_services: list = field(default_factory=list)
    session_token: str = "tok-abc"
    timestamp: str = "2026-06-30T10:00:00Z"


class Snapshot:
    """Stub for app.policy.models.Snapshot."""

    pass


# ── Register stubs in sys.modules ───────────────────────────────────────
# Only stub modules that DON'T exist on disk yet (other team members'
# code). Do NOT stub app.pdp.detectors — that's our real package.

_stubs = {
    "app": types.ModuleType("app"),
    "app.pdp": types.ModuleType("app.pdp"),
    "app.pdp.decision": types.ModuleType("app.pdp.decision"),
    "app.identity": types.ModuleType("app.identity"),
    "app.identity.context": types.ModuleType("app.identity.context"),
    "app.policy": types.ModuleType("app.policy"),
    "app.policy.models": types.ModuleType("app.policy.models"),
}

_stubs["app.pdp.decision"].Disposition = Disposition
_stubs["app.pdp.decision"].Signal = Signal
_stubs["app.identity.context"].RequestContext = RequestContext
_stubs["app.policy.models"].Snapshot = Snapshot

# Wire package hierarchy so Python resolves app.pdp.detectors on disk
_stubs["app"].__path__ = [os.path.join(PROJECT_ROOT, "app")]
_stubs["app.pdp"].__path__ = [os.path.join(PROJECT_ROOT, "app", "pdp")]
_stubs["app.identity"].__path__ = [os.path.join(PROJECT_ROOT, "app", "identity")]
_stubs["app.policy"].__path__ = [os.path.join(PROJECT_ROOT, "app", "policy")]

# Set parent references
_stubs["app"].pdp = _stubs["app.pdp"]
_stubs["app"].identity = _stubs["app.identity"]
_stubs["app"].policy = _stubs["app.policy"]
_stubs["app.pdp"].decision = _stubs["app.pdp.decision"]
_stubs["app.identity"].context = _stubs["app.identity.context"]
_stubs["app.policy"].models = _stubs["app.policy.models"]

for mod_name, mod in _stubs.items():
    sys.modules.setdefault(mod_name, mod)


# ── Shared pytest fixtures ──────────────────────────────────────────────


@pytest.fixture
def eng() -> RequestContext:
    """Mock RequestContext for an engineer."""
    return RequestContext(user_id="eng-042", role="Engineer", tenant="firm-alpha")


@pytest.fixture
def comp() -> RequestContext:
    """Mock RequestContext for a compliance officer."""
    return RequestContext(user_id="comp-007", role="ComplianceOfficer", tenant="firm-alpha")


@pytest.fixture
def snap() -> Snapshot:
    """Mock policy snapshot."""
    return Snapshot()
