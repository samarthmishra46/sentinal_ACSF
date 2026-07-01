# ADHIRAJ-DAY2
"""End-to-end integration test for the first red-team prompts.

Owner: Adhiraj (Integration + Glue).
Day-2 gate: the first four red-team prompts (RT-01..RT-04) must produce the
correct decision when driven through the full stack via POST /v1/chat.

What this covers from the Day-2 task:
  * "Run the full stack end-to-end with the first 4 red-team prompts."
  * "Write integration test script that POSTs to /v1/chat and checks
     response + DB record."

Two integration realities this test documents (report items, not fixes):
  1. /v1/chat takes ``user_id``, not ``role`` — so each red-team ``role`` is
     mapped to a seeded EIM user (app/identity/eim_client.py).
  2. Audit persistence is console-only today: app/pep/audit_hook.default_sink()
     returns a ConsoleAuditSink that prints one ``[AUDIT] {json}`` line per
     request; nothing is written to a database yet. Until Nikhil's
     AsyncAuditLogger is wired at that swap point, "check the DB record" is
     checked at the record-emitted level (captured stdout). See the audit-record
     assertions below and the report to Ryan/Nikhil.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app.main import app

# The red-team prompts declare a role; the ingress API authenticates a user_id.
# Map each role to one of Anamika's 5 seeded EIM users.
ROLE_TO_USER = {
    "Engineer": "u-001",
    "ComplianceOfficer": "u-005",
    "Support": "u-003",
    "SecurityReviewer": "u-004",
}

_PROMPTS_FILE = Path(__file__).parent / "redteam" / "prompts.yaml"


def _load_prompts() -> list[dict]:
    # utf-8 is required: prompts.yaml has Unicode box-drawing chars in comments.
    with open(_PROMPTS_FILE, encoding="utf-8") as fh:
        return yaml.safe_load(fh)["prompts"]


# The Day-2 gate is the FIRST FOUR prompts in file order (RT-01..RT-04).
FIRST_FOUR = _load_prompts()[:4]

client = TestClient(app)


def _post(case: dict):
    """POST one red-team case to /v1/chat, returning the parsed response body."""
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


@pytest.mark.parametrize("case", FIRST_FOUR, ids=[c["id"] for c in FIRST_FOUR])
def test_first_four_decisions(case: dict):
    """The Day-2 gate: each of the first 4 prompts returns the expected decision."""
    body, _ = _post(case)
    assert body["decision"] == case["expected_decision"], (
        f"{case['id']} ({case['category']}): "
        f"expected {case['expected_decision']}, got {body['decision']}"
    )


@pytest.mark.parametrize("case", FIRST_FOUR, ids=[c["id"] for c in FIRST_FOUR])
def test_first_four_audit_record_emitted(case: dict, capsys):
    """An audit record is emitted per request, matching the enforced decision.

    NOTE: this asserts on the console-emitted record, not a DB row — DB
    persistence is not wired yet (report to Ryan/Nikhil).
    """
    body, user_id = _post(case)
    record = _last_audit_record(capsys.readouterr().out)
    assert record is not None, f"{case['id']}: no [AUDIT] record was emitted"
    assert record["decision"] == body["decision"]
    assert record["user_id"] == user_id
    assert record["prompt_hash"], f"{case['id']}: audit record missing prompt_hash"


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            c,
            id=c["id"],
            marks=(
                pytest.mark.xfail(
                    reason=(
                        "RT-02 is STOPped at Stage 3 (authz, R-AUTH) because "
                        "ComplianceOfficer is not permitted to chat, so Sneha's "
                        "SMR scanner (R-02) never runs. Decision is correct but the "
                        "rule provenance is wrong. Reported to Anamika (authz) / "
                        "Sneha (intent). Also risks RT-12 (ComplianceOfficer ALLOW)."
                    ),
                    strict=False,
                )
                if c["id"] == "RT-02"
                else ()
            ),
        )
        for c in FIRST_FOUR
    ],
)
def test_first_four_rule_provenance(case: dict, capsys):
    """The rule that fired should match the prompt's expected_rule.

    This is stricter than the gate: it verifies the RIGHT control caught the
    prompt, not just that some control did. RT-02 is a known xfail (see reason).
    """
    _post(case)
    record = _last_audit_record(capsys.readouterr().out)
    assert record is not None, f"{case['id']}: no audit record"
    assert record["rule_triggered"] == case["expected_rule"], (
        f"{case['id']}: expected rule {case['expected_rule']}, "
        f"but {record['rule_triggered']} fired"
    )
