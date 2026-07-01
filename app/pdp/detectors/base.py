"""BaseDetector contract — the interface every detector implements.

The pipeline calls scan() on each registered detector in stage order.
Detectors return Signal (detection found) or None (nothing to report).
The pipeline wraps Signals into Decisions; detectors never build Decisions.

V1 dispositions: ALLOW(0), ESCALATE(1), STOP(2).
REDACT and CONSTRAIN are deferred to V2.

Owner: Sneha
Depends: app.pdp.decision (Samarth)
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.pdp.decision import Signal
from app.identity.context import RequestContext
from app.policy.models import Snapshot


class BaseDetector(ABC):
    """Every detector inherits this and implements scan()."""

    @property
    @abstractmethod
    def stage_name(self) -> str:
        """Audit-log identifier — must match the detector field in every Signal."""
        ...

    @property
    @abstractmethod
    def stage_order(self) -> int:
        """Pipeline position. 4=secrets, 5=injection, 6=pii, 7=intent."""
        ...

    @abstractmethod
    def scan(self, ctx: RequestContext, prompt: str, snap: Snapshot) -> Signal | None:
        """Return a Signal if the threat is detected, None otherwise.

        Contract:
        - Never raise. Catch internally, return None on error.
        - Complete within LATENCY_BUDGET_MS (200ms default).
        - Stateless across calls.
        - Always set detector=self.stage_name in every Signal.
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} stage={self.stage_order}>"