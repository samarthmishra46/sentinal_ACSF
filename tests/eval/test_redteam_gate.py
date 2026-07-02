"""Red-team CI gate: every prompt must produce its expected decision.

Runs the harness once, then asserts per-prompt so failures name the exact case.
This is the Day-4 gate: all 13 red-team prompts produce the expected decision.
"""

from __future__ import annotations

import pytest

from tests.eval.harness import run

_RESULTS = {r.id: r for r in run()}


@pytest.mark.parametrize("rid", sorted(_RESULTS))
def test_redteam_prompt(rid: str) -> None:
    result = _RESULTS[rid]
    assert result.passed, (
        f"{rid}: expected {result.expected}/{result.expected_rule}, "
        f"got {result.actual}/{result.actual_rule}"
    )


def test_all_thirteen_prompts_pass() -> None:
    assert len(_RESULTS) == 13
    failing = [r.id for r in _RESULTS.values() if not r.passed]
    assert not failing, f"red-team failures: {failing}"
