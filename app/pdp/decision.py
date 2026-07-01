"""Core decision contracts for the PDP.

This module is a *leaf*: it imports nothing internal so that import order can
never block the rest of the team. Every stage returns a ``Decision``; the
combiner aggregates many ``Decision`` objects into the single one the PEP acts
on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Disposition(IntEnum):
    """Outcome of an evaluation, ordered by strictness.

    Modelled as an ``IntEnum`` so the combiner can pick the strictest verdict
    with a plain numeric ``max()``: higher value == stricter.

    NOTE: the full design has 5 outcomes (adding REDACT and ALLOW+CONSTRAIN),
    but those are deferred to V2. The enum is intentionally extensible and the
    numeric ordering will be revisited then.
    """

    ALLOW = 0
    ESCALATE = 1
    STOP = 2


@dataclass(frozen=True)
class Signal:
    """One detection signal produced by a detector or infra component.

    Signals are the audit-grade evidence behind a ``Decision``. A ``Decision``
    carries the full set so the audit log can explain *why* a verdict landed.
    """

    detector: str
    rule_id: str | None
    disposition: Disposition
    reason: str
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    """The unit every pipeline stage returns and the combiner emits."""

    disposition: Disposition
    reason: str
    signals: tuple[Signal, ...] = ()
    # Version of the policy snapshot this decision was evaluated against.
    # Stamped by the pipeline from the exact snapshot it used, so the audit log
    # cites the right version even if a hot-reload happens afterwards. Defaults
    # to "" at construction; stages don't know the version, the pipeline does.
    policy_version: str = ""

    @property
    def decisive_signal(self) -> Signal | None:
        """The strictest signal behind this decision, or None if there are none.

        Single canonical source for the audit log's ``rule_triggered`` /
        ``policy_triggered`` fields, so the PEP and the audit logger always cite
        the *same* signal.
        """
        if not self.signals:
            return None
        return max(self.signals, key=lambda s: s.disposition)

    @classmethod
    def allow(cls, reason: str = "", signals: tuple[Signal, ...] = ()) -> "Decision":
        """Build an ALLOW decision."""
        return cls(Disposition.ALLOW, reason, signals)

    @classmethod
    def escalate(cls, reason: str = "", signals: tuple[Signal, ...] = ()) -> "Decision":
        """Build an ESCALATE decision (route to human / step-up review)."""
        return cls(Disposition.ESCALATE, reason, signals)

    @classmethod
    def stop(cls, reason: str = "", signals: tuple[Signal, ...] = ()) -> "Decision":
        """Build a STOP decision (block the request outright)."""
        return cls(Disposition.STOP, reason, signals)

    # REDACT / CONSTRAIN classmethods are deferred to V2 — see Disposition.
