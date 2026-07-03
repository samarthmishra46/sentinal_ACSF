"""Latency profiler for the PDP input pipeline (Samarth · Day 4).

Measures per-stage and end-to-end latency of the *real* pipeline against the
red-team prompts and reports mean / p50 / p95 / max. This answers the Day-4
task "run latency profiling — identify any stage over budget" and backs the
coordinator's success signal, "red-team suite includes a latency assertion"
(see ``test_latency_gate.py``).

Budgets (from the unified plan):
  - Input pipeline (stages 1–7): well under ``INPUT_BUDGET_MS`` (150 ms).
  - End-to-end request: ``settings.LATENCY_BUDGET_MS`` (200 ms).

The profiling is deliberately *external*: it wraps each stage with a timer and
runs with the decision cache disabled, so the production hot path in
``app/pdp/pipeline.py`` stays untouched and zero-overhead. Disabling the cache
means every iteration exercises all stages (a warm cache would short-circuit
repeats and hide the real per-stage cost we want to measure).

Entry points:
  - ``profile(...)`` -> ``LatencyReport``  (used by the pytest gate)
  - ``python -m tests.eval.latency``       (prints a per-stage table)
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from app.config import settings
from app.identity.context import RequestContext
from app.pdp.factory import default_stages
from app.pdp.pipeline import Pipeline, Stage
from app.policy.store import PolicyStore

PROMPTS_FILE = Path(__file__).resolve().parents[1] / "redteam" / "prompts.yaml"

# Input-pipeline budget: stages 1–7 must complete in <150 ms total (unified plan).
INPUT_BUDGET_MS = 150.0
# End-to-end request budget (PEP + pipeline + output), from Adhiraj's config.
END_TO_END_BUDGET_MS = float(settings.LATENCY_BUDGET_MS)

# Stage name -> pipeline stage number, for a readable report. Stages 1 (normalize)
# and 2 (identity) run upstream in the PEP, so the engine owns stages 3–7.
_STAGE_NUMBERS = {
    "_authz_stage": 3,
    "secrets_scanner": 4,
    "injection_scanner": 5,
    "pii_detector": 6,
    "intent_compliance_scanner": 7,
}


@dataclass(frozen=True)
class Stat:
    """Summary statistics for a series of latency samples (milliseconds)."""

    name: str
    count: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    max_ms: float


@dataclass(frozen=True)
class LatencyReport:
    """Result of a profiling run."""

    total: Stat                       # end-to-end evaluate() wall time
    per_stage: list[Stat]             # one Stat per stage, in pipeline order
    cache_hit_ms: float               # cost of a warm-cache repeat (Day-3 feature)
    input_budget_ms: float
    end_to_end_budget_ms: float
    samples: int

    @property
    def passed(self) -> bool:
        """True if the pipeline stays within the input-pipeline budget."""
        return self.total.p95_ms < self.input_budget_ms and all(
            s.p95_ms < self.input_budget_ms for s in self.per_stage
        )


def _percentile(sorted_samples: list[float], pct: float) -> float:
    """Nearest-rank percentile of an already-sorted list (empty -> 0.0)."""
    if not sorted_samples:
        return 0.0
    k = max(0, min(len(sorted_samples) - 1, round(pct / 100.0 * len(sorted_samples) + 0.5) - 1))
    return sorted_samples[k]


def _stat(name: str, samples: list[float]) -> Stat:
    """Build a Stat from raw millisecond samples."""
    if not samples:
        return Stat(name, 0, 0.0, 0.0, 0.0, 0.0)
    ordered = sorted(samples)
    return Stat(
        name=name,
        count=len(ordered),
        mean_ms=sum(ordered) / len(ordered),
        p50_ms=_percentile(ordered, 50),
        p95_ms=_percentile(ordered, 95),
        max_ms=max(ordered),
    )


def _timed_stage(inner: Stage, bucket: list[float]) -> Stage:
    """Wrap a stage so each call appends its wall time (ms) to ``bucket``."""

    def stage(ctx: Any, prompt: str, snap: Any) -> Optional[Any]:
        start = time.perf_counter()
        try:
            return inner(ctx, prompt, snap)
        finally:
            bucket.append((time.perf_counter() - start) * 1000.0)

    stage.__name__ = getattr(inner, "__name__", "stage")
    return stage


def _instrument() -> tuple[list[Stage], dict[str, list[float]]]:
    """Return timed copies of the real stages plus their per-stage buckets."""
    buckets: dict[str, list[float]] = {}
    wrapped: list[Stage] = []
    for stage in default_stages():
        name = getattr(stage, "__name__", repr(stage))
        buckets[name] = []
        wrapped.append(_timed_stage(stage, buckets[name]))
    return wrapped, buckets


def _ctx(entry: dict[str, Any]) -> RequestContext:
    """Build a RequestContext from a prompt entry (mirrors the red-team harness)."""
    tenant = entry.get("tenant", "firm-alpha")
    return RequestContext(
        user_id=f"user-{entry['id']}",
        role=entry.get("role", "Engineer"),
        tenant=tenant,
        owned_services=[tenant],
        session_token="latency-token",
    )


def _load_prompts() -> list[dict[str, Any]]:
    import yaml  # lazy: only the harness/profiler needs PyYAML

    data = yaml.safe_load(PROMPTS_FILE.read_text(encoding="utf-8")) or {}
    return data.get("prompts", [])


def profile(iterations: int = 200, warmup: int = 20) -> LatencyReport:
    """Profile the pipeline over the red-team prompts and return a LatencyReport.

    Runs every prompt ``iterations`` times (after ``warmup`` unmeasured passes to
    let the interpreter settle). The cache is disabled so all stages run every
    time. A separate warm-cache pipeline measures the cache-hit cost.
    """
    prompts = [(_ctx(e), e["prompt"]) for e in _load_prompts()]

    wrapped, buckets = _instrument()
    pipeline = Pipeline(PolicyStore(), stages=wrapped, cache_size=0)

    # Warmup: run without recording (also discards warmup entries from buckets).
    for _ in range(warmup):
        for ctx, prompt in prompts:
            pipeline.evaluate(ctx, prompt)
    for bucket in buckets.values():
        bucket.clear()

    total_samples: list[float] = []
    for _ in range(iterations):
        for ctx, prompt in prompts:
            start = time.perf_counter()
            pipeline.evaluate(ctx, prompt)
            total_samples.append((time.perf_counter() - start) * 1000.0)

    per_stage = [
        _stat(getattr(s, "__name__", repr(s)), buckets[getattr(s, "__name__", repr(s))])
        for s in wrapped
    ]

    return LatencyReport(
        total=_stat("end-to-end", total_samples),
        per_stage=per_stage,
        cache_hit_ms=_measure_cache_hit(prompts),
        input_budget_ms=INPUT_BUDGET_MS,
        end_to_end_budget_ms=END_TO_END_BUDGET_MS,
        samples=len(total_samples),
    )


def _measure_cache_hit(prompts: list[tuple[RequestContext, str]], iterations: int = 200) -> float:
    """Median cost of a warm-cache repeat — demonstrates the Day-3 LRU cache."""
    if not prompts:
        return 0.0
    warm = Pipeline(PolicyStore(), stages=default_stages())
    ctx, prompt = prompts[0]
    warm.evaluate(ctx, prompt)  # prime the cache (this is a miss)
    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        warm.evaluate(ctx, prompt)  # cache hit: skips all stages
        samples.append((time.perf_counter() - start) * 1000.0)
    return _percentile(sorted(samples), 50)


def _fmt(stat: Stat, number: Optional[int]) -> str:
    label = stat.name if number is None else f"Stage {number} · {stat.name}"
    return (
        f"{label:<34} {stat.mean_ms:8.4f} {stat.p50_ms:8.4f} "
        f"{stat.p95_ms:8.4f} {stat.max_ms:8.4f}"
    )


def main() -> int:
    """Print a per-stage latency table; exit non-zero if over the input budget."""
    report = profile()
    print(f"Latency profile — {report.samples} samples per column, cache disabled\n")
    print(f"{'STAGE':<34} {'mean':>8} {'p50':>8} {'p95':>8} {'max':>8}   (ms)")
    print("-" * 78)
    for stat in report.per_stage:
        print(_fmt(stat, _STAGE_NUMBERS.get(stat.name)))
    print("-" * 78)
    print(_fmt(report.total, None))
    print("-" * 78)
    print(
        f"input-pipeline budget: {report.input_budget_ms:.0f} ms  ·  "
        f"end-to-end budget: {report.end_to_end_budget_ms:.0f} ms  ·  "
        f"warm-cache hit (p50): {report.cache_hit_ms:.4f} ms"
    )
    verdict = "PASS — every stage well under budget" if report.passed else "FAIL — a stage is over budget"
    print(f"\n{verdict} (end-to-end p95 = {report.total.p95_ms:.4f} ms)")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
