"""Evaluation pipeline: run ordered stages, combine their verdicts.

Imports ``decision``, ``combiner`` and ``policy.models``. ``RequestContext``
lives in Anamika's ``app/identity/context.py`` (not written yet) and is
referenced under TYPE_CHECKING only — never imported at runtime — so import
order can't block the team.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Callable, Optional

from app.pdp.combiner import combine
from app.pdp.decision import Decision, Disposition
from app.policy.models import Snapshot
from app.policy.store import PolicyStore

if TYPE_CHECKING:
    from app.identity.context import RequestContext

# A stage inspects the request and returns a Decision, or None for "no objection".
Stage = Callable[["RequestContext", str, Snapshot], Optional[Decision]]


class Pipeline:
    """Runs ordered stages against a request and combines their verdicts."""

    def __init__(self, store: PolicyStore, stages: Sequence[Stage]) -> None:
        """Bind the pipeline to a policy store and an ordered list of stages."""
        self._store = store
        self._stages = stages

    def evaluate(self, ctx: "RequestContext", prompt: str) -> Decision:
        """Evaluate a request and return the combined Decision.

        This is the public contract Ryan's PEP calls.
        """
        # Read the active snapshot once so every stage sees a consistent policy.
        snap = self._store.active

        # Seed with a baseline ALLOW so the happy path resolves to ALLOW and the
        # combiner's empty->ESCALATE guard stays purely defensive.
        # TECH-LEAD DEFAULT (flag for team confirmation): this reconciles
        # "fail-closed empty -> ESCALATE" with "happy path -> ALLOW".
        verdicts: list[Decision] = [Decision.allow(reason="no detector objected")]

        # Cheapest-first / fail-fast: run in order, short-circuit on STOP.
        for stage in self._stages:
            verdict = stage(ctx, prompt, snap)
            if verdict is None:
                continue
            verdicts.append(verdict)
            if verdict.disposition is Disposition.STOP:
                break

        return combine(verdicts)
