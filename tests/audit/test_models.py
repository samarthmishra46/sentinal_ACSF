"""Unit tests for the AuditRecord model and hashing."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from enum import IntEnum

import pytest

from app.audit.models import (
    COLUMNS,
    DECISIONS,
    AuditRecord,
    hash_prompt,
)


# --- hash_prompt -------------------------------------------------------------

def test_hash_prompt_is_64_hex_and_deterministic():
    h1 = hash_prompt("hello world")
    h2 = hash_prompt("hello world")
    assert h1 == h2
    assert re.fullmatch(r"[0-9a-f]{64}", h1)


def test_hash_prompt_differs_per_input():
    assert hash_prompt("a") != hash_prompt("b")


def test_hash_prompt_rejects_non_str():
    with pytest.raises(TypeError):
        hash_prompt(b"bytes")  # type: ignore[arg-type]


# --- raw prompt is never recoverable ----------------------------------------

def test_raw_prompt_never_stored():
    prompt = "John Smith, TFN 123-456-789"
    rec = AuditRecord.new(
        user_id="u1", role="Engineer", decision="STOP", prompt=prompt
    )
    blob = json.dumps(rec.to_dict())
    assert prompt not in blob
    assert "123-456-789" not in blob
    assert rec.prompt_hash == hash_prompt(prompt)


# --- factory / auto fields ---------------------------------------------------

def test_new_autofills_request_id_and_timestamp():
    rec = AuditRecord.new(
        user_id="u1", role="Engineer", decision="ALLOW", prompt="hi"
    )
    # request_id is a valid UUID
    uuid.UUID(rec.request_id)
    # timestamp is ISO-8601 with timezone
    assert rec.timestamp.endswith("+00:00") or rec.timestamp.endswith("Z")
    assert rec.policy_version == "v1.0"


def test_new_requires_exactly_one_of_prompt_or_hash():
    with pytest.raises(ValueError):
        AuditRecord.new(user_id="u", role="r", decision="ALLOW")
    with pytest.raises(ValueError):
        AuditRecord.new(
            user_id="u",
            role="r",
            decision="ALLOW",
            prompt="x",
            prompt_hash=hash_prompt("x"),
        )


def test_accepts_precomputed_hash():
    h = hash_prompt("precomputed")
    rec = AuditRecord.new(user_id="u", role="r", decision="ALLOW", prompt_hash=h)
    assert rec.prompt_hash == h


# --- validation --------------------------------------------------------------

def test_invalid_decision_rejected():
    with pytest.raises(ValueError):
        AuditRecord.new(
            user_id="u", role="r", decision="BLOCK", prompt="x"
        )


def test_all_known_decisions_accepted():
    for d in DECISIONS:
        rec = AuditRecord.new(user_id="u", role="r", decision=d, prompt="x")
        assert rec.decision == d


def test_invalid_actor_type_rejected():
    with pytest.raises(ValueError):
        AuditRecord.new(
            user_id="u", role="r", decision="ALLOW", prompt="x", actor_type="A-99"
        )


def test_empty_actor_type_allowed():
    rec = AuditRecord.new(
        user_id="u", role="r", decision="ALLOW", prompt="x", actor_type=""
    )
    assert rec.actor_type == ""


def test_bad_prompt_hash_rejected():
    with pytest.raises(ValueError):
        AuditRecord(
            user_id="u",
            role="r",
            service="",
            prompt_hash="tooshort",
            decision="ALLOW",
            reason="",
            actor_type="",
            rule_triggered="",
            latency_ms=1.0,
        )


# --- serialization round-trip ------------------------------------------------

def test_to_row_matches_columns_and_round_trips():
    rec = AuditRecord.new(
        user_id="u1",
        role="Engineer",
        decision="STOP",
        prompt="secret",
        service="svc",
        reason="why",
        actor_type="A-01",
        rule_triggered="R-01",
        policy_triggered="P-01",
        latency_ms=42.0,
        signals=["pii:TFN", "pii:DOB"],
    )
    row = rec.to_row()
    assert len(row) == len(COLUMNS)
    # signals are JSON-encoded in the row
    signals_idx = COLUMNS.index("signals")
    assert json.loads(row[signals_idx]) == ["pii:TFN", "pii:DOB"]

    rehydrated = AuditRecord.from_row(row)
    assert rehydrated.decision == "STOP"
    assert rehydrated.signals == ["pii:TFN", "pii:DOB"]
    assert rehydrated.rule_triggered == "R-01"
    assert rehydrated.prompt_hash == rec.prompt_hash


# --- from_decision duck-typing ----------------------------------------------

class _FakeDisposition:
    """Stand-in for Samarth's enum (has .name)."""

    def __init__(self, name: str) -> None:
        self.name = name


class _FakeDecision:
    def __init__(self):
        self.disposition = _FakeDisposition("STOP")
        self.reason = "blocked"
        self.rule_triggered = "R-06"
        self.policy_triggered = "P-03"
        self.signals = ["injection:DAN"]


class _FakeContext:
    user_id = "u-42"
    role = "Engineer"
    service = "assistant"
    actor_type = "A-04"


def test_from_decision_reads_teammate_objects():
    rec = AuditRecord.from_decision(
        _FakeDecision(), _FakeContext(), prompt="ignore previous instructions"
    )
    assert rec.decision == "STOP"
    assert rec.user_id == "u-42"
    assert rec.actor_type == "A-04"
    assert rec.rule_triggered == "R-06"
    assert rec.signals == ["injection:DAN"]
    assert rec.prompt_hash == hash_prompt("ignore previous instructions")


def test_from_decision_numeric_disposition():
    class NumDecision:
        disposition = 2  # Samarth's STOP=2
        prompt_hash = hash_prompt("x")

    rec = AuditRecord.from_decision(NumDecision(), _FakeContext())
    assert rec.decision == "STOP"


def test_from_decision_missing_verdict_fails_closed():
    class Empty:
        prompt_hash = hash_prompt("x")

    rec = AuditRecord.from_decision(Empty(), _FakeContext())
    # No disposition -> fail closed to ESCALATE rather than ALLOW.
    assert rec.decision == "ESCALATE"


# --- from_decision against the team's REAL contracts ------------------------
# Faithful replicas of app/pdp/decision.py (Samarth) and app/identity/context.py
# (Anamika) so we prove integration works against their actual shapes.

class _Disposition(IntEnum):
    ALLOW = 0
    ESCALATE = 1
    STOP = 2


@dataclass(frozen=True)
class _Signal:
    detector: str
    rule_id: str | None
    disposition: _Disposition
    reason: str
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class _Decision:
    disposition: _Disposition
    reason: str
    signals: tuple = ()
    policy_version: str = "v1.0"

    @property
    def decisive_signal(self):
        return max(self.signals, key=lambda s: s.disposition) if self.signals else None


@dataclass
class _RequestContext:
    user_id: str = "eng-042"
    role: str = "Engineer"
    owned_services: list = field(default_factory=lambda: ["risk-scoring", "kyc"])
    actor_type: str = "A-01"


def test_from_decision_matches_real_samarth_and_anamika_types():
    sig = _Signal(
        detector="secrets_scanner",
        rule_id="R-07",
        disposition=_Disposition.STOP,
        reason="Credential detected: database connection string.",
        metadata={"severity": "HIGH"},
    )
    decision = _Decision(_Disposition.STOP, sig.reason, (sig,), policy_version="v1.2")
    ctx = _RequestContext()

    rec = AuditRecord.from_decision(
        decision, ctx, prompt="postgres://u:p@h/db", latency_ms=8.4
    )

    assert rec.decision == "STOP"
    assert rec.rule_triggered == "R-07"          # pulled from decisive_signal.rule_id
    assert rec.signals == ["secrets_scanner"]     # rendered from Signal.detector
    assert rec.service == "risk-scoring"          # first of owned_services
    assert rec.actor_type == "A-01"
    assert rec.policy_version == "v1.2"           # stamped from the Decision
    assert rec.prompt_hash == hash_prompt("postgres://u:p@h/db")


def test_from_decision_picks_strictest_signal_rule():
    allow_sig = _Signal("pii_detector", "R-01", _Disposition.ALLOW, "ok")
    stop_sig = _Signal("secrets_scanner", "R-07", _Disposition.STOP, "creds")
    decision = _Decision(_Disposition.STOP, "creds", (allow_sig, stop_sig))
    rec = AuditRecord.from_decision(decision, _RequestContext(), prompt="x")
    # decisive_signal is the STOP one -> R-07, not R-01.
    assert rec.rule_triggered == "R-07"


def test_from_decision_policy_and_actor_overrides():
    # Ryan resolves policy_triggered from the shared catalog and reads actor_type
    # from the EIM-classified context, then passes both in; overrides must win.
    sig = _Signal("secrets_scanner", "R-07", _Disposition.STOP, "creds")
    decision = _Decision(_Disposition.STOP, "creds", (sig,))
    ctx = _RequestContext(actor_type="A-01")
    rec = AuditRecord.from_decision(
        decision, ctx, prompt="x",
        policy_triggered="P-07",   # from policy_for(snapshot, "R-07")["policy_id"]
        actor_type="A-04",         # EIM-classified, overrides ctx default
    )
    assert rec.policy_triggered == "P-07"
    assert rec.actor_type == "A-04"
    assert rec.rule_triggered == "R-07"
