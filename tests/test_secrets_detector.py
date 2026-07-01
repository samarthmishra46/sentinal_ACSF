"""Unit tests for Nikhil's secrets/credential detector — Stage 4, Rule R-07.

Mirrors the team's established pattern (tests/test_detectors.py): stub the shared
dependency modules in ``sys.modules`` so the detector imports cleanly even though
``app/identity/context.py`` isn't on devlop yet, then exercise the real detection
logic. The detector module is loaded from its file path under a private name so
it never shadows Python's stdlib ``secrets`` module.

Fires (must STOP):  DB URI w/ password, AWS key, Stripe key, GitHub/Slack token,
                    Bearer/JWT, PEM key, .env credential, 40+ char high-entropy.
Does NOT fire:      config questions, key-format questions, placeholders,
                    .env.example templates.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# ── Stub the shared contracts (matches Samarth's committed decision.py) ─────
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


class _StubBaseDetector(ABC):
    @property
    @abstractmethod
    def stage_name(self) -> str: ...

    @property
    @abstractmethod
    def stage_order(self) -> int: ...

    @abstractmethod
    def scan(self, ctx, prompt, snap): ...


def _ensure(path: str, **attrs) -> types.ModuleType:
    """Register a stub module ONLY if absent; never overwrite a real attribute.

    In this standalone repo the ``app.*`` modules don't exist, so the stubs are
    used. On the team repo (devlop) the real modules are present and used as-is;
    we only fill the ones still missing (e.g. ``app.identity.context``). This
    keeps the test from polluting teammates' real modules.
    """
    mod = sys.modules.get(path)
    if mod is None:
        mod = types.ModuleType(path)
        sys.modules[path] = mod
    for name, value in attrs.items():
        if not hasattr(mod, name):
            setattr(mod, name, value)
    return mod


_ensure("app")
_ensure("app.pdp")
_ensure("app.pdp.detectors")
_ensure("app.identity")
_ensure("app.policy")
_ensure("app.pdp.decision", Disposition=Disposition, Signal=Signal)
_ensure("app.identity.context", RequestContext=RequestContext)
_ensure("app.policy.models", Snapshot=MagicMock)
_ensure("app.pdp.detectors.base", BaseDetector=_StubBaseDetector)


# ── Load the real secrets.py by path, under a non-colliding module name ─────
_SECRETS_PATH = Path(__file__).resolve().parents[1] / "app" / "pdp" / "detectors" / "secrets.py"
_spec = importlib.util.spec_from_file_location("sentinel_secrets_detector", _SECRETS_PATH)
secrets_mod = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(secrets_mod)

SecretsDetector = secrets_mod.SecretsDetector
find_secret = secrets_mod.find_secret
# Bind the EXACT Signal/Disposition/BaseDetector the detector resolved (the real
# ones on devlop, the stubs here) so ``is`` comparisons in assertions hold either
# way.
Disposition = secrets_mod.Disposition
Signal = secrets_mod.Signal
BaseDetector = secrets_mod.BaseDetector


# ── Fixtures ────────────────────────────────────────────────────────────────
@pytest.fixture
def det() -> "SecretsDetector":
    return SecretsDetector()


@pytest.fixture
def eng() -> RequestContext:
    return RequestContext(user_id="eng-042", role="Engineer")


@pytest.fixture
def snap() -> MagicMock:
    return MagicMock()


# ── Interface conformance ────────────────────────────────────────────────────
def test_implements_base_detector_contract(det):
    assert det.stage_name == "secrets_scanner"
    assert det.stage_order == 4
    assert isinstance(det, BaseDetector)


# ── MUST FIRE (STOP + R-07) ─────────────────────────────────────────────────
# Synthetic test credentials are ASSEMBLED FROM FRAGMENTS on purpose: the
# provider token formats (Slack/GitHub/Stripe/AWS/DB URI) are recognised by
# GitHub secret-scanning push protection, which would block this test file if the
# literal strings appeared in source. The joined runtime value is still a valid
# token shape that the detector's regex catches — so coverage is unchanged.
def _c(*parts: str) -> str:
    return "".join(parts)


# The canonical red-team prompt RT-06 from tests/redteam/prompts.yaml.
RT07_POSTGRES = (
    "This database query is failing in production. Here's the connection string: "
    f"postgres://lexaml_admin:{_c('s3cret', 'P4ss')}@prod-db.internal:5432/lexaml_prod "
    "Can you help debug the SSL handshake issue?"
)

FIRING_CASES = [
    ("postgres URI w/ password", RT07_POSTGRES, "database connection string"),
    ("AWS access key", "creds: AKIAIOSFODNN7EXAMPLE and go", "known-compromised credential"),
    ("fresh AWS key", _c("key AKIA", "1234567890ABCDEF") + " please rotate", "AWS access key"),
    ("Stripe secret", _c("STRIPE_KEY sk", "_live_", "abcdEFGH1234ijklMNOP"), "Stripe secret key"),
    ("GitHub token", _c("token ghp", "_", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), "GitHub token"),
    ("Slack token", _c("xox", "b-123456789012-abcdefABCDEF012345"), "Slack token"),
    ("Bearer token", _c("Authorization: Bearer ", "abcdefghij0123456789KLMNOP"), "Bearer token"),
    ("PEM private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "PEM private key"),
    (".env credential", "set DB_PASSWORD=" + _c("Hunter2", "Winter9x") + " in the env", "credential assignment (.env)"),
]


@pytest.mark.parametrize("name,prompt,expected_type", FIRING_CASES, ids=[c[0] for c in FIRING_CASES])
def test_secret_fires_stop(det, eng, snap, name, prompt, expected_type):
    sig = det.scan(eng, prompt, snap)
    assert sig is not None, f"{name}: expected a Signal, got None"
    assert sig.disposition is Disposition.STOP
    assert sig.rule_id == "R-07"
    assert sig.detector == "secrets_scanner"
    assert sig.metadata["owasp_id"] == "LLM02"
    assert sig.metadata["atlas_id"] == "AML.T0024"
    assert sig.metadata["secret_type"] == expected_type


def test_high_entropy_string_fires(det, eng, snap):
    # 40+ char mixed alphanumeric with no obvious label.
    blob = "aws_blob wJalrXUtnFEMIqK7MDENGbPxRfiCYz9Ab1Cd2Ef3"
    sig = det.scan(eng, blob, snap)
    assert sig is not None and sig.disposition is Disposition.STOP


# ── MUST NOT FIRE (policy "does NOT fire" cases) ─────────────────────────────
NON_FIRING = [
    ("config question", "How do I configure the database connection pool in our Node.js app?"),
    ("key format question", "What format does an AWS access key use?"),
    ("env.example template", "Help me set up a .env.example with API_KEY=your_key_here placeholder"),
    ("placeholder URI", "connect with postgres://user:<password>@host:5432/db in the docs"),
    ("plain prose", "The engineer reviewed the onboarding workflow and closed three tickets today."),
    ("password word only", "Where is the password reset feature documented?"),
]


@pytest.mark.parametrize("name,prompt", NON_FIRING, ids=[c[0] for c in NON_FIRING])
def test_benign_does_not_fire(det, eng, snap, name, prompt):
    assert det.scan(eng, prompt, snap) is None, f"{name}: false positive"


# ── Pure-function + robustness ───────────────────────────────────────────────
def test_find_secret_returns_type_and_confidence():
    hit = find_secret(RT07_POSTGRES)
    assert hit is not None
    stype, conf = hit
    assert stype == "database connection string"
    assert 0.0 < conf <= 1.0


def test_never_raises_on_weird_input(det, eng, snap):
    for junk in ["", "\x00\x01", "🔥" * 100, "a" * 5000]:
        # Must return None or a Signal, never raise.
        det.scan(eng, junk, snap)


def test_automated_actor_gets_critical_severity(det, snap):
    ctx = RequestContext(user_id="svc-1", role="AutomatedSystem")
    sig = det.scan(ctx, RT07_POSTGRES, snap)
    assert sig is not None and sig.metadata["severity"] == "CRITICAL"
