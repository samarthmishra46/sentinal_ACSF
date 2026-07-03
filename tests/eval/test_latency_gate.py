"""Latency gate: the input pipeline must stay well within its budget.

Backs the coordinator's Day-4 success signal — "red-team suite includes a
latency assertion" — and enforces the unified plan's rule that stages 1–7
complete in <150 ms. The real pipeline runs roughly three orders of magnitude
under that (sub-millisecond p95), so these assertions are *not* flaky: they
exist to catch a catastrophic regression, e.g. a real NLP model or a network
call landing on the hot path.

Uses a smaller iteration count than the CLI profiler to keep the test fast.
"""

from __future__ import annotations

from tests.eval.latency import END_TO_END_BUDGET_MS, INPUT_BUDGET_MS, profile

# One profiling run shared across the assertions below.
_REPORT = profile(iterations=50, warmup=10)


def test_end_to_end_p95_within_input_budget() -> None:
    """The whole input pipeline (all stages) stays under the 150 ms budget."""
    assert _REPORT.total.p95_ms < INPUT_BUDGET_MS, (
        f"input pipeline p95 {_REPORT.total.p95_ms:.3f} ms exceeds "
        f"{INPUT_BUDGET_MS:.0f} ms budget"
    )


def test_worst_single_request_within_end_to_end_budget() -> None:
    """Even the slowest single evaluate() leaves headroom under the 200 ms budget."""
    assert _REPORT.total.max_ms < END_TO_END_BUDGET_MS, (
        f"slowest request {_REPORT.total.max_ms:.3f} ms exceeds "
        f"{END_TO_END_BUDGET_MS:.0f} ms end-to-end budget"
    )


def test_no_single_stage_exceeds_budget() -> None:
    """No individual stage may blow the input budget on its own."""
    over = [s.name for s in _REPORT.per_stage if s.p95_ms >= INPUT_BUDGET_MS]
    assert not over, f"stages over the {INPUT_BUDGET_MS:.0f} ms budget: {over}"


def test_every_stage_was_actually_measured() -> None:
    """Guard the profiler itself: every stage produced samples (nothing skipped)."""
    assert _REPORT.per_stage, "no stages were profiled"
    for stat in _REPORT.per_stage:
        assert stat.count > 0, f"stage {stat.name!r} recorded no samples"
