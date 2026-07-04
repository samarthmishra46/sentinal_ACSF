# RYAN-DAY4
"""Day-4 gate — all 13 red-team prompts driven through the FULL PEP stack.

Owner: Ryan (PEP).

Samarth's harness (tests/eval/harness.py) scores the 13 prompts against the PDP
pipeline *directly*. Adhiraj's tests/test_integration_redteam.py drives the first
four through POST /v1/chat. This test closes the Day-4 gate at the level my seat
is responsible for: the complete request path a real caller hits —

    POST /v1/chat
      -> identity resolution (Anamika's EIMClient, user_id -> RequestContext)
      -> pipeline.evaluate  (Samarth's PDP: Sneha's detectors, Anamika's authz)
      -> enforcement.apply  (my STOP / ESCALATE / ALLOW dispatch + egress scan)
      -> audit sink          (ConsoleAuditSink emits one [AUDIT] line)

It asserts four things per prompt, strongest first:
  1. the enforced *decision* matches expected  (the Day-4 gate);
  2. the *rule* that fired matches expected_rule (right control, not just any);
  3. the *response body shape* matches the disposition my PEP applied;
  4. an *audit record* was emitted that agrees with the response.

Integration realities (documented, not bugs):
  * /v1/chat authenticates a ``user_id``; the prompts declare a ``role``. Each
    role is mapped to one of Anamika's 5 seeded EIM users (ROLE_TO_USER).
  * Those seeded users live in tenant ``org-acme``; the prompts *say*
    ``firm-alpha``. In the end-to-end path the tenant comes from the EIM seed,
    not the prompt text, so RT-08/RT-09 (bulk / cross-org) fire on prompt
    content, which is what the gate checks.
  * RESOLVED since Adhiraj's Day-2 xfail: RT-02 (ComplianceOfficer) is no longer
    STOPped at Stage-3 authz — Anamika's Day-4 get_default_action() lets it reach
    Sneha's SMR scanner, so the decisive rule is R-02 (correct provenance). No
    xfail is needed here; if RT-02 regresses to R-AUTH this test will catch it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app.main import app

# The red-team prompts declare a role; the ingress API authenticates a user_id.
# Map each role to one of Anamika's 5 seeded EIM users (app/identity/eim_client.py).
ROLE_TO_USER = {
    "Engineer": "u-001",
    "ComplianceOfficer": "u-005",
    "Support": "u-003",
    "SecurityReviewer": "u-004",
}

_PROMPTS_FILE = Path(__file__).parent / "redteam" / "prompts.yaml"


def _load_prompts() -> list[dict]:
    # utf-8: prompts.yaml has Unicode box-drawing chars in its comments.
    with open(_PROMPTS_FILE, encoding="utf-8") as fh:
        return yaml.safe_load(fh)["prompts"]


ALL_PROMPTS = _load_prompts()
_IDS = [c["id"] for c in ALL_PROMPTS]

client = TestClient(app)


def _post(case: dict) -> tuple[dict, str]:
    """POST one red-team case to /v1/chat; return (response_body, user_id)."""
    user_id = ROLE_TO_USER.get(case["role"], "u-001")
    resp = client.post("/v1/chat", json={"prompt": case["prompt"], "user_id": user_id})
    assert resp.status_code == 200, f"{case['id']}: HTTP {resp.status_code}"
    return resp.json(), user_id


def _last_audit_record(captured_out: str) -> dict | None:
    """Parse the last '[AUDIT] {json}' line the ConsoleAuditSink printed."""
    lines = [ln for ln in captured_out.splitlines() if ln.startswith("[AUDIT] ")]
    if not lines:
        return None
    return json.loads(lines[-1][len("[AUDIT] ") :])


def _escalation_emitted(captured_out: str) -> bool:
    """True if the escalation queue logged an ESCALATION event this request."""
    for ln in captured_out.splitlines():
        ln = ln.strip()
        if ln.startswith("{") and '"event": "ESCALATION"' in ln:
            return True
    return False


@pytest.mark.parametrize("case", ALL_PROMPTS, ids=_IDS)
def test_redteam_decision(case: dict) -> None:
    """THE DAY-4 GATE: every prompt returns its expected decision end-to-end."""
    body, _ = _post(case)
    assert body["decision"] == case["expected_decision"], (
        f"{case['id']} ({case['category']}): "
        f"expected {case['expected_decision']}, got {body['decision']}"
    )


@pytest.mark.parametrize("case", ALL_PROMPTS, ids=_IDS)
def test_redteam_rule_provenance(case: dict, capsys) -> None:
    """The RIGHT control caught the prompt (or none, for the ALLOW controls).

    Stricter than the gate. DEFAULT means no specific rule should fire.
    """
    _post(case)
    record = _last_audit_record(capsys.readouterr().out)
    assert record is not None, f"{case['id']}: no [AUDIT] record was emitted"
    fired = record["rule_triggered"]
    if case["expected_rule"] == "DEFAULT":
        assert fired is None, f"{case['id']}: expected no rule, but {fired} fired"
    else:
        assert fired == case["expected_rule"], (
            f"{case['id']}: expected rule {case['expected_rule']}, but {fired} fired"
        )


@pytest.mark.parametrize("case", ALL_PROMPTS, ids=_IDS)
def test_redteam_enforcement_shape(case: dict, capsys) -> None:
    """The response body matches the disposition my PEP applied.

    STOP     -> no answer is returned; the reason cites the policy/rule.
    ESCALATE -> caller told it is under review; the queue logged an event.
    ALLOW    -> a (stub) assistant answer is returned.
    """
    body, _ = _post(case)
    out = capsys.readouterr().out
    disposition = case["expected_decision"]

    if disposition == "STOP":
        assert body["response"] is None, f"{case['id']}: STOP must not return an answer"
        assert "blocked under" in body["reason"].lower(), (
            f"{case['id']}: STOP reason should cite the policy, got {body['reason']!r}"
        )
    elif disposition == "ESCALATE":
        assert body["response"], f"{case['id']}: ESCALATE should return a holding message"
        assert _escalation_emitted(out), (
            f"{case['id']}: ESCALATE should enqueue an ESCALATION event"
        )
    else:  # ALLOW
        assert body["response"], f"{case['id']}: ALLOW should return an assistant answer"


@pytest.mark.parametrize("case", ALL_PROMPTS, ids=_IDS)
def test_redteam_audit_record(case: dict, capsys) -> None:
    """Every request emits an audit record that agrees with the response."""
    body, user_id = _post(case)
    record = _last_audit_record(capsys.readouterr().out)
    assert record is not None, f"{case['id']}: no [AUDIT] record was emitted"
    assert record["decision"] == body["decision"], f"{case['id']}: audit/response decision mismatch"
    assert record["user_id"] == user_id, f"{case['id']}: audit user_id mismatch"
    assert record["prompt_hash"], f"{case['id']}: audit record missing prompt_hash"


def test_all_thirteen_prompts_pass() -> None:
    """Summary gate: all 13 prompts, correct decision AND correct rule, no xfails."""
    assert len(ALL_PROMPTS) == 13, "expected exactly 13 red-team prompts"
    failures: list[str] = []
    for case in ALL_PROMPTS:
        user_id = ROLE_TO_USER.get(case["role"], "u-001")
        resp = client.post(
            "/v1/chat", json={"prompt": case["prompt"], "user_id": user_id}
        )
        if resp.json().get("decision") != case["expected_decision"]:
            failures.append(case["id"])
    assert not failures, f"red-team failures through /v1/chat: {failures}"
