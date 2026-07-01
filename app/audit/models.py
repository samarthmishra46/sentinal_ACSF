"""AuditRecord model and helpers.

The field set below is the one *locked on Day 1 morning* in the sprint plan and
the Master Analysis (Part 4, action 6). Every Sentinel decision produces exactly
one AuditRecord, which the :class:`~app.audit.logger.AsyncAuditLogger` persists to
an append-only table.

Two invariants the policy document is strict about:

* **Raw prompts are never stored.** The only way a prompt enters a record is
  through :func:`hash_prompt`, which yields a SHA-256 hex digest. There is no
  ``prompt`` field on the record at all, so leaking raw text is structurally
  impossible.
* **The record is decoupled from teammates' types.** ``decision`` /
  ``actor_type`` / ``rule_triggered`` are plain strings, so this module does not
  import Samarth's ``decision.py`` or Ryan's ``RequestContext`` (which do not
  exist yet on Day 1). :meth:`AuditRecord.from_decision` consumes those objects
  by duck typing *when* they exist.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Iterable, Sequence

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    # These live in teammates' modules and may not exist yet on Day 1. Importing
    # them only under TYPE_CHECKING keeps this module standalone and runnable.
    from app.pdp.decision import Decision  # noqa: F401
    from app.identity.context import RequestContext  # noqa: F401


# --- Controlled vocabularies -------------------------------------------------

#: The five unified outcomes (Master Analysis 3.1). V1 actively uses the first
#: four; ALLOW_CONSTRAIN (R-11) is wired for the field but is a V2 behaviour.
DECISIONS: frozenset[str] = frozenset(
    {"ALLOW", "STOP", "REDACT", "ESCALATE", "ALLOW_CONSTRAIN"}
)

#: The four actor types from the policy document's Actors & Context Model.
ACTOR_TYPES: frozenset[str] = frozenset({"A-01", "A-02", "A-03", "A-04"})

#: Default policy bundle version stamped onto every record.
POLICY_VERSION: str = "v1.0"

#: Column order shared by the SQL schemas and :meth:`AuditRecord.to_row`. Keep
#: this in lock-step with ``schema.sql`` / ``schema_sqlite.sql``.
COLUMNS: tuple[str, ...] = (
    "request_id",
    "ts",
    "user_id",
    "role",
    "service",
    "prompt_hash",
    "policy_triggered",
    "decision",
    "reason",
    "actor_type",
    "rule_triggered",
    "latency_ms",
    "signals",
    "policy_version",
)


def hash_prompt(prompt: str) -> str:
    """Return the SHA-256 hex digest of ``prompt``.

    This is the *only* sanctioned path for a prompt to enter an audit record.
    The digest is 64 lowercase hex characters and is deterministic, so the same
    prompt always maps to the same hash (useful for correlating repeat attempts)
    while remaining non-reversible.
    """
    if not isinstance(prompt, str):
        raise TypeError(f"prompt must be str, got {type(prompt).__name__}")
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _utc_now_iso() -> str:
    """Current time as an ISO-8601 string in UTC (matches Lex-AML's format)."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class AuditRecord:
    """One immutable line in the Sentinel audit trail.

    Use :meth:`new` (auto-fills ``request_id`` + ``timestamp``) or
    :meth:`from_decision` rather than constructing directly, unless you are
    rehydrating a row from the database.
    """

    user_id: str
    role: str
    service: str
    prompt_hash: str
    decision: str
    reason: str
    actor_type: str
    rule_triggered: str
    latency_ms: float
    # Fields with sensible defaults / auto-generation come last.
    policy_triggered: str = ""
    signals: list[str] = field(default_factory=list)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=_utc_now_iso)
    policy_version: str = POLICY_VERSION

    def __post_init__(self) -> None:
        if self.decision not in DECISIONS:
            raise ValueError(
                f"decision must be one of {sorted(DECISIONS)}, got {self.decision!r}"
            )
        # actor_type is allowed to be empty (e.g. unauthenticated pre-identity
        # stage) but if present it must be a known code.
        if self.actor_type and self.actor_type not in ACTOR_TYPES:
            raise ValueError(
                f"actor_type must be one of {sorted(ACTOR_TYPES)} or '', "
                f"got {self.actor_type!r}"
            )
        if len(self.prompt_hash) != 64 or not _is_hex(self.prompt_hash):
            raise ValueError(
                "prompt_hash must be a 64-char SHA-256 hex digest; "
                "use hash_prompt() — never store the raw prompt"
            )
        if not isinstance(self.signals, list):
            raise TypeError("signals must be a list[str]")
        self.latency_ms = float(self.latency_ms)

    # --- Factories -----------------------------------------------------------

    @classmethod
    def new(
        cls,
        *,
        user_id: str,
        role: str,
        decision: str,
        prompt: str | None = None,
        prompt_hash: str | None = None,
        service: str = "",
        reason: str = "",
        actor_type: str = "",
        rule_triggered: str = "",
        policy_triggered: str = "",
        latency_ms: float = 0.0,
        signals: Iterable[str] | None = None,
        policy_version: str = POLICY_VERSION,
    ) -> "AuditRecord":
        """Build a record, hashing ``prompt`` for you if given.

        Exactly one of ``prompt`` or ``prompt_hash`` must be supplied. Passing
        the raw ``prompt`` is the common case at call sites; it is hashed
        immediately and discarded.
        """
        if (prompt is None) == (prompt_hash is None):
            raise ValueError("supply exactly one of `prompt` or `prompt_hash`")
        digest = prompt_hash if prompt_hash is not None else hash_prompt(prompt)
        return cls(
            user_id=user_id,
            role=role,
            service=service,
            prompt_hash=digest,
            decision=decision,
            reason=reason,
            actor_type=actor_type,
            rule_triggered=rule_triggered,
            policy_triggered=policy_triggered,
            latency_ms=latency_ms,
            signals=list(signals or []),
            policy_version=policy_version,
        )

    @classmethod
    def from_decision(
        cls,
        decision: Any,
        context: Any = None,
        *,
        prompt: str | None = None,
        latency_ms: float = 0.0,
        policy_version: str = POLICY_VERSION,
    ) -> "AuditRecord":
        """Build a record from teammates' objects without importing their types.

        ``decision`` is expected to look like Samarth's ``Decision`` (attributes
        such as ``disposition``/``decision``, ``reason``, ``rule_triggered``,
        ``policy_triggered``, ``signals``). ``context`` is expected to look like
        Ryan/Anamika's ``RequestContext`` (``user_id``, ``role``, ``service``,
        ``actor_type``). Everything is read via :func:`getattr` with fallbacks,
        so this works against whatever shape those modules land on.
        """
        disp = _first_attr(decision, ("disposition", "decision", "outcome"))
        decision_str = _disposition_to_str(disp)

        signals_raw = _first_attr(decision, ("signals",), default=None)
        signals = _normalise_signals(signals_raw)

        ctx = context if context is not None else decision
        prompt_hash = _first_attr(decision, ("prompt_hash",), default=None)
        if prompt_hash is None and prompt is not None:
            prompt_hash = hash_prompt(prompt)
        if prompt_hash is None:
            raise ValueError(
                "no prompt_hash on the decision and no `prompt` provided; "
                "cannot build a record without one"
            )

        # rule/policy: Samarth's Decision carries them on its *decisive* Signal
        # (Decision has no rule_triggered field). Prefer explicit attrs, then
        # fall back to the strictest signal's rule_id — matching how the PEP and
        # audit hook cite the same signal.
        dsig = _decisive_signal(decision)
        rule = _first_attr(decision, ("rule_triggered", "rule"), default=None)
        if rule is None and dsig is not None:
            rule = getattr(dsig, "rule_id", None)
        policy = _first_attr(decision, ("policy_triggered", "policy"), default=None)

        # policy_version: prefer the value the pipeline stamped on the Decision.
        pv = _first_attr(decision, ("policy_version",), default=None)

        return cls(
            user_id=str(_first_attr(ctx, ("user_id", "user"), default="unknown")),
            role=str(_first_attr(ctx, ("role",), default="unknown")),
            service=str(_context_service(ctx)),
            prompt_hash=prompt_hash,
            decision=decision_str,
            reason=str(_first_attr(decision, ("reason", "message"), default="")),
            actor_type=str(_first_attr(ctx, ("actor_type", "actor"), default="")),
            rule_triggered=str(rule or ""),
            policy_triggered=str(policy or ""),
            latency_ms=float(
                _first_attr(decision, ("latency_ms",), default=latency_ms)
            ),
            signals=signals,
            policy_version=str(pv) if pv else policy_version,
        )

    # --- Serialization -------------------------------------------------------

    def to_row(self) -> tuple[Any, ...]:
        """Return the value tuple in :data:`COLUMNS` order for a DB insert.

        ``signals`` is JSON-encoded so a single representation works for both the
        SQLite (TEXT) and PostgreSQL (JSONB) columns.
        """
        return (
            self.request_id,
            self.timestamp,
            self.user_id,
            self.role,
            self.service,
            self.prompt_hash,
            self.policy_triggered,
            self.decision,
            self.reason,
            self.actor_type,
            self.rule_triggered,
            self.latency_ms,
            json.dumps(self.signals),
            self.policy_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Plain dict (signals kept as a list) — handy for logging/JSON APIs."""
        return asdict(self)

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> "AuditRecord":
        """Rehydrate a record from a DB row in :data:`COLUMNS` order.

        Used by the demo/query helpers when reading the trail back.
        """
        data = dict(zip(COLUMNS, row))
        signals = data["signals"]
        if isinstance(signals, str):
            signals = json.loads(signals or "[]")
        return cls(
            request_id=data["request_id"],
            timestamp=data["ts"],
            user_id=data["user_id"],
            role=data["role"],
            service=data["service"],
            prompt_hash=data["prompt_hash"],
            policy_triggered=data["policy_triggered"] or "",
            decision=data["decision"],
            reason=data["reason"] or "",
            actor_type=data["actor_type"] or "",
            rule_triggered=data["rule_triggered"] or "",
            latency_ms=float(data["latency_ms"] or 0.0),
            signals=list(signals),
            policy_version=data["policy_version"],
        )


# --- small internal helpers --------------------------------------------------


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _first_attr(obj: Any, names: Iterable[str], default: Any = None) -> Any:
    """Return the first present, non-None attribute (or mapping key) from names."""
    for name in names:
        if obj is None:
            break
        if isinstance(obj, dict):
            if name in obj and obj[name] is not None:
                return obj[name]
            continue
        val = getattr(obj, name, None)
        if val is not None:
            return val
    return default


def _disposition_to_str(disp: Any) -> str:
    """Coerce an enum/int/str disposition into one of :data:`DECISIONS`."""
    if disp is None:
        return "ESCALATE"  # fail-closed default if a decision lacks a verdict
    # Enum-like: prefer .name
    name = getattr(disp, "name", None)
    if isinstance(name, str):
        return _canonical_decision(name)
    if isinstance(disp, str):
        return _canonical_decision(disp)
    # Samarth's numeric scale (ALLOW=0, ESCALATE=1, REDACT=1.5, STOP=2 ...).
    if isinstance(disp, (int, float)):
        mapping = {0: "ALLOW", 1: "ESCALATE", 2: "STOP"}
        if disp == 1.5:
            return "REDACT"
        return mapping.get(int(disp), "ESCALATE")
    return "ESCALATE"


def _canonical_decision(value: str) -> str:
    v = value.strip().upper().replace("+", "_").replace(" ", "_").replace("-", "_")
    if v in ("ALLOW_CONSTRAIN", "ALLOW_CONSTRAINT", "ALLOWCONSTRAIN"):
        return "ALLOW_CONSTRAIN"
    return v if v in DECISIONS else "ESCALATE"


def _normalise_signals(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    out: list[str] = []
    for s in raw:
        # Signal may be a dataclass/obj; render something human-readable. Samarth's
        # Signal exposes ``.detector`` (what the PEP/audit hook cite), so try that
        # first, then generic label-ish attributes.
        if isinstance(s, str):
            out.append(s)
        else:
            label = _first_attr(s, ("detector", "label", "name", "id", "rule"), default=None)
            out.append(str(label) if label is not None else str(s))
    return out


def _decisive_signal(decision: Any) -> Any:
    """Return the strictest signal on a decision (Samarth's ``decisive_signal``).

    Uses the ``decisive_signal`` property if present; otherwise picks the signal
    with the highest ``disposition``. None-safe.
    """
    sig = _first_attr(decision, ("decisive_signal",), default=None)
    if sig is not None:
        return sig
    signals = _first_attr(decision, ("signals",), default=None)
    if not signals:
        return None
    try:
        return max(signals, key=lambda s: getattr(s, "disposition", 0))
    except (TypeError, ValueError):
        return None


def _context_service(ctx: Any) -> str:
    """Resolve the service string from a context.

    Anamika's ``RequestContext`` exposes ``owned_services`` (a list); older stubs
    used ``service``/``owned_service`` (scalar). Handle both.
    """
    scalar = _first_attr(ctx, ("service", "owned_service"), default=None)
    if scalar:
        return str(scalar)
    owned = _first_attr(ctx, ("owned_services",), default=None)
    if owned:
        try:
            return str(owned[0])
        except (IndexError, TypeError, KeyError):
            return ""
    return ""
