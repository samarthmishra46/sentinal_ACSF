"""Verdict combiner: collapse many stage Decisions into one.

Imports only ``decision`` (a leaf), keeping the dependency DAG clean.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.pdp.decision import Decision


def combine(verdicts: Sequence[Decision]) -> Decision:
    """Collapse a sequence of stage verdicts into a single Decision.

    - Fail-closed: an empty sequence yields ESCALATE. The pipeline seeds a
      baseline ALLOW so this branch is purely defensive in normal operation.
    - Otherwise the strictest disposition wins (numeric ``max``), the winning
      verdict supplies the top-level reason, and signals from *all* verdicts
      are aggregated so the audit log keeps the full evidence set.
    """
    if not verdicts:
        return Decision.escalate(reason="fail-closed: no verdicts produced")

    winner = max(verdicts, key=lambda d: d.disposition)
    signals = tuple(s for v in verdicts for s in v.signals)
    return Decision(winner.disposition, winner.reason, signals)
