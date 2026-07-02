"""Red-team evaluation harness.

Loads the red-team prompts (``tests/redteam/prompts.yaml``), runs each through
the real PDP pipeline, and compares the actual Decision to the expected one.

Two entry points:
  - ``run()`` — returns structured results (used by the pytest gate).
  - ``python -m tests.eval.harness`` — prints a human-readable pass/fail table.

The Day-3/Day-4 gate is: every prompt produces its expected decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.identity.context import RequestContext
from app.pdp.factory import build_pipeline
from app.policy.store import PolicyStore

PROMPTS_FILE = Path(__file__).resolve().parents[1] / "redteam" / "prompts.yaml"


@dataclass(frozen=True)
class Result:
    """Outcome of one red-team prompt."""

    id: str
    expected: str
    actual: str
    expected_rule: str
    actual_rule: str | None
    passed: bool
    category: str


def _ctx(entry: dict[str, Any]) -> RequestContext:
    """Build a RequestContext from a prompt entry (defaults for absent fields)."""
    tenant = entry.get("tenant", "firm-alpha")
    return RequestContext(
        user_id=f"user-{entry['id']}",
        role=entry.get("role", "Engineer"),
        tenant=tenant,
        owned_services=[tenant],
        session_token="redteam-token",
    )


def _load_prompts() -> list[dict[str, Any]]:
    import yaml  # lazy: only the harness needs PyYAML

    data = yaml.safe_load(PROMPTS_FILE.read_text(encoding="utf-8")) or {}
    return data.get("prompts", [])


def run() -> list[Result]:
    """Run every red-team prompt through a fresh pipeline and score it."""
    pipeline = build_pipeline(PolicyStore())
    results: list[Result] = []
    for entry in _load_prompts():
        decision = pipeline.evaluate(_ctx(entry), entry["prompt"])
        sig = decision.decisive_signal
        actual_rule = sig.rule_id if sig else None
        expected = entry.get("expected_decision", "ALLOW")
        # A "DEFAULT" expected_rule means no specific rule should fire.
        expected_rule = entry.get("expected_rule", "DEFAULT")
        decision_ok = decision.disposition.name == expected
        rule_ok = expected_rule == "DEFAULT" or actual_rule == expected_rule
        results.append(
            Result(
                id=entry["id"],
                expected=expected,
                actual=decision.disposition.name,
                expected_rule=expected_rule,
                actual_rule=actual_rule,
                passed=decision_ok and rule_ok,
                category=entry.get("category", ""),
            )
        )
    return results


def main() -> int:
    """Print a pass/fail table; return the number of failures (exit code)."""
    results = run()
    print(f"{'ID':<7} {'EXPECT':<9} {'ACTUAL':<9} {'RULE(exp/act)':<18} {'':<4} CATEGORY")
    print("-" * 78)
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        rules = f"{r.expected_rule}/{r.actual_rule}"
        print(f"{r.id:<7} {r.expected:<9} {r.actual:<9} {rules:<18} {mark:<4} {r.category}")
    passed = sum(1 for r in results if r.passed)
    print("-" * 78)
    print(f"{passed}/{len(results)} passed")
    return len(results) - passed


if __name__ == "__main__":
    raise SystemExit(main())
