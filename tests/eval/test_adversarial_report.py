"""Guard test for the adversarial harness (Samarth · Day-5).

Non-gating: it does NOT assert a minimum detection rate (that would make the
suite fail whenever we discover a new bypass — the opposite of what we want).
It only proves the harness itself runs end-to-end and produces sane metrics, so
a refactor can't silently break the measurement tool.
"""

from __future__ import annotations

from tests.eval.adversarial import run_adversarial


def test_harness_runs_and_produces_metrics() -> None:
    report = run_adversarial(per_strategy=1, seed=0)  # small = fast
    assert report.malicious, "expected some malicious variants"
    assert report.benign, "expected some benign variants"
    assert 0.0 <= report.detection_rate <= 1.0
    assert 0.0 <= report.false_positive_rate <= 1.0


def test_original_redteam_prompts_are_detected() -> None:
    # Sanity floor: the 9 *unmutated* red-team (RT-*) malicious originals must
    # still be caught — this is the existing 13-prompt gate viewed through the
    # harness. The curated M-* corpus deliberately includes rules-only bypasses
    # (the compliance-intent gap Phases 2-4 close), so it is NOT asserted here;
    # those are tracked as bypasses in docs/v2_eval_results.md, not as failures.
    report = run_adversarial(per_strategy=1, seed=0)
    originals = [r for r in report.malicious
                 if r.case.strategy == "original" and r.case.parent_id.startswith("RT-")]
    missed = [r.case.parent_id for r in originals if not r.detected]
    assert not missed, f"red-team originals slipped through: {missed}"
