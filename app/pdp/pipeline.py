"""Evaluation pipeline: run ordered stages, combine their verdicts.

Imports ``decision``, ``combiner`` and ``policy.models``. ``RequestContext``
lives in Anamika's ``app/identity/context.py`` and is referenced under
TYPE_CHECKING only — never imported at runtime — so import order can't block
the team.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Callable, NamedTuple, Optional

from app.pdp.combiner import combine
from app.pdp.decision import Decision, Disposition, Signal
from app.policy.models import Snapshot
from app.policy.store import PolicyStore

if TYPE_CHECKING:
    from app.identity.context import RequestContext

# A stage inspects the request and returns a Decision, or None for "no objection".
Stage = Callable[["RequestContext", str, Snapshot], Optional[Decision]]

DEFAULT_CACHE_SIZE = 1024


class CacheInfo(NamedTuple):
    """Snapshot of decision-cache stats (for tests + monitoring)."""

    hits: int
    misses: int
    size: int
    capacity: int


class Pipeline:
    """Runs ordered stages against a request and combines their verdicts.

    Carries a small LRU decision cache: identical requests against the *same*
    policy snapshot reuse the prior Decision. The cache is keyed to the snapshot
    object identity, so any hot-reload (which swaps in a new snapshot) transparently
    invalidates it — a stale policy can never serve a cached verdict.
    """

    def __init__(
        self,
        store: PolicyStore,
        stages: Sequence[Stage],
        cache_size: int = DEFAULT_CACHE_SIZE,
    ) -> None:
        """Bind the pipeline to a policy store and an ordered list of stages."""
        self._store = store
        self._stages = stages
        self._cache_size = cache_size
        self._cache: "OrderedDict[tuple, Decision]" = OrderedDict()
        self._cache_snapshot_id: Optional[int] = None
        self._hits = 0
        self._misses = 0

    def evaluate(self, ctx: "RequestContext", prompt: str) -> Decision:
        """Evaluate a request and return the combined Decision.

        This is the public contract Ryan's PEP calls.
        """
        # Read the active snapshot once so every stage sees a consistent policy.
        snap = self._store.active

        # Snapshot swapped (hot-reload)? Drop the cache — it belonged to the old policy.
        if id(snap) != self._cache_snapshot_id:
            self._cache.clear()
            self._cache_snapshot_id = id(snap)

        if self._cache_size > 0:
            key = self._cache_key(ctx, prompt)
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)  # LRU: mark most-recently-used
                self._hits += 1
                return cached
            self._misses += 1
            decision = self._evaluate(ctx, prompt, snap)
            self._cache[key] = decision
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)  # evict least-recently-used
            return decision

        return self._evaluate(ctx, prompt, snap)

    def _evaluate(self, ctx: "RequestContext", prompt: str, snap: Snapshot) -> Decision:
        """Run the ordered stages against a fixed snapshot and combine verdicts."""
        # Seed with a baseline ALLOW so the happy path resolves to ALLOW and the
        # combiner's empty->ESCALATE guard stays purely defensive.
        verdicts: list[Decision] = [Decision.allow(reason="no detector objected")]

        # Cheapest-first / fail-fast: run in order, short-circuit on STOP.
        for stage in self._stages:
            try:
                verdict = stage(ctx, prompt, snap)
            except Exception as exc:
                # Fail-closed: a crashing detector must never propagate out of
                # evaluate(). Convert it to ESCALATE (the team's convention for
                # infra failure) so the request is held for review, not answered
                # un-screened. Does not short-circuit; only STOP does.
                verdicts.append(self._stage_error(stage, exc))
                continue
            if verdict is None:
                continue
            verdicts.append(verdict)
            if verdict.disposition is Disposition.STOP:
                break

        # Stamp the snapshot version onto the result so the audit log cites the
        # exact policy version used, race-free against a later hot-reload.
        return replace(combine(verdicts), policy_version=snap.version)

    @staticmethod
    def _cache_key(ctx: "RequestContext", prompt: str) -> tuple:
        """Cache key from the request attributes that affect the verdict.

        Uses role/tenant/owned_services (authz + cross-org) + prompt. Uses
        ``getattr`` so a non-RequestContext ctx (e.g. in unit tests) never crashes.
        """
        owned = getattr(ctx, "owned_services", None) or ()
        return (
            getattr(ctx, "role", None),
            getattr(ctx, "tenant", None),
            tuple(owned),
            prompt,
        )

    def cache_info(self) -> CacheInfo:
        """Return current cache stats."""
        return CacheInfo(self._hits, self._misses, len(self._cache), self._cache_size)

    @staticmethod
    def _stage_error(stage: Stage, exc: Exception) -> Decision:
        """Build the fail-closed ESCALATE verdict for a stage that raised."""
        name = getattr(stage, "__name__", repr(stage))
        reason = f"fail-closed: stage '{name}' raised {type(exc).__name__}"
        signal = Signal(
            detector="pipeline",
            rule_id=None,
            disposition=Disposition.ESCALATE,
            reason=reason,
            metadata={"stage": name, "error": repr(exc)},
        )
        return Decision.escalate(reason=reason, signals=(signal,))
