"""Rolling per-user behaviour tracker — the stateful core of the session layer.

Keeps a bounded, time-windowed history of each user's requests and derives simple
features from it:

  * queries in the last hour
  * distinct customer identifiers referenced in the window
  * requests touching services outside the user's owned_services
  * off-hours activity
  * consecutive-ESCALATE / block streak

An anomaly on any feature ESCALATEs (never STOPs — a human decides, and the review
becomes a labelled example that feeds the Phase-3 dataset). Thresholds are explicit
and cite-able ("42 queries in the last hour exceeds the 20/hour baseline for role
Support") rather than a black-box score. An isolation-forest second opinion is the
documented next step once there is enough real traffic to fit it.

Thread-safe: the PEP serves concurrent requests, so all state mutation is under a
lock. In-memory and per-process for V1 of this layer; the durable source of truth
is Nikhil's audit log (app/audit/queries.for_user) — noted as the production
upgrade so counters survive a restart and span workers.
"""

from __future__ import annotations

import re
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Optional

# Customer-identifier shapes worth counting toward "distinct customers touched".
# Deliberately broad: names are not counted (too noisy), structured ids are.
_CUSTOMER_ID = re.compile(
    r"\b(?:cust(?:omer)?[-_ ]?\d{3,}|acc(?:ount)?[-_ ]?\d{3,}|"
    r"[A-Z]{5}[0-9]{4}[A-Z]|\d{3}[-.\s]\d{3}[-.\s]\d{3})\b",
    re.IGNORECASE,
)


@dataclass
class BehaviourVerdict:
    """Outcome of a behavioural check — an anomaly with a human-readable reason."""

    anomalous: bool
    reason: str = ""
    feature: str = ""
    value: float = 0.0
    threshold: float = 0.0


@dataclass
class _Event:
    ts: datetime
    customer_ids: frozenset[str]
    off_owned: bool
    escalated: bool


@dataclass
class _UserState:
    events: Deque[_Event] = field(default_factory=deque)
    escalate_streak: int = 0


class BehaviourTracker:
    """Bounded, time-windowed per-user history with explicit anomaly thresholds."""

    def __init__(
        self,
        window_seconds: int = 3600,
        max_queries_per_hour: int = 60,
        max_distinct_customers: int = 25,
        max_off_owned_per_hour: int = 15,
        max_escalate_streak: int = 3,
        off_hours: tuple[int, int] = (1, 5),  # local hours [start, end) flagged
    ) -> None:
        self._window = window_seconds
        self._max_q = max_queries_per_hour
        self._max_cust = max_distinct_customers
        self._max_off = max_off_owned_per_hour
        self._max_streak = max_escalate_streak
        self._off_start, self._off_end = off_hours
        self._users: dict[str, _UserState] = defaultdict(_UserState)
        self._lock = threading.Lock()

    @staticmethod
    def extract_customer_ids(prompt: str) -> frozenset[str]:
        """Structured customer identifiers referenced in the prompt."""
        return frozenset(m.group(0).lower() for m in _CUSTOMER_ID.finditer(prompt))

    def _prune(self, state: _UserState, now: datetime) -> None:
        cutoff = now.timestamp() - self._window
        while state.events and state.events[0].ts.timestamp() < cutoff:
            state.events.popleft()

    def record_and_check(
        self,
        user_id: str,
        prompt: str,
        owned_services: list[str],
        service: str | None = None,
        now: Optional[datetime] = None,
    ) -> BehaviourVerdict:
        """Record this request and return whether the user's pattern is anomalous.

        ``service`` is the service the request targets; when it is outside
        ``owned_services`` the request counts toward the off-owned feature.
        """
        now = now or datetime.now(timezone.utc)
        off_owned = bool(service) and service not in (owned_services or [])
        event = _Event(
            ts=now,
            customer_ids=self.extract_customer_ids(prompt),
            off_owned=off_owned,
            escalated=False,  # set later via note_decision
        )
        with self._lock:
            state = self._users[user_id]
            state.events.append(event)
            self._prune(state, now)

            n_queries = len(state.events)
            distinct = set().union(*(e.customer_ids for e in state.events)) \
                if state.events else set()
            n_off = sum(1 for e in state.events if e.off_owned)
            hour = now.astimezone().hour
            off_hours = self._off_start <= hour < self._off_end

            # Cheapest / most decisive checks first.
            if n_queries > self._max_q:
                return self._flag("query_rate", n_queries, self._max_q,
                                  f"{n_queries} queries in the last hour exceeds the "
                                  f"{self._max_q}/hour baseline")
            if len(distinct) > self._max_cust:
                return self._flag("distinct_customers", len(distinct), self._max_cust,
                                  f"{len(distinct)} distinct customers referenced this "
                                  f"hour exceeds the {self._max_cust} baseline "
                                  "(possible bulk assembly)")
            if n_off > self._max_off:
                return self._flag("off_owned_services", n_off, self._max_off,
                                  f"{n_off} requests this hour target services outside "
                                  f"owned_services (baseline {self._max_off})")
            if off_hours and n_queries > max(5, self._max_q // 4):
                return self._flag("off_hours_volume", n_queries, self._max_q // 4,
                                  f"{n_queries} queries during off-hours "
                                  f"({self._off_start:02d}:00-{self._off_end:02d}:00)")
        return BehaviourVerdict(anomalous=False)

    def note_decision(self, user_id: str, escalated_or_blocked: bool,
                      now: Optional[datetime] = None) -> BehaviourVerdict:
        """Update the escalate/block streak after the pipeline decides.

        Returns an anomaly verdict if the streak crosses the threshold — repeated
        blocks are a probing signature.
        """
        now = now or datetime.now(timezone.utc)
        with self._lock:
            state = self._users[user_id]
            if escalated_or_blocked:
                state.escalate_streak += 1
            else:
                state.escalate_streak = 0
            streak = state.escalate_streak
            if streak > self._max_streak:
                return self._flag("escalate_streak", streak, self._max_streak,
                                  f"{streak} consecutive blocked/escalated requests "
                                  f"(baseline {self._max_streak}) — probing pattern")
        return BehaviourVerdict(anomalous=False)

    @staticmethod
    def _flag(feature: str, value: float, threshold: float, reason: str) -> BehaviourVerdict:
        return BehaviourVerdict(anomalous=True, reason=reason, feature=feature,
                                value=float(value), threshold=float(threshold))

    def reset(self) -> None:
        """Clear all state (tests / process handoff)."""
        with self._lock:
            self._users.clear()
