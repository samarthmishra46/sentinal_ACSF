"""
Secrets / Credential Detector — Stage 4 (R-07). Real implementation (Day 2).

Detects infrastructure secrets pasted into prompts before they reach the model:
DB connection strings with embedded passwords, cloud API keys (AWS/GCP/Stripe/
GitHub/Slack), Bearer/JWT tokens, PEM private keys, ``.env`` assignments, and
long high-entropy strings that statistically resemble secrets.

Detection strategy (cheapest-first, like the PII detector):
  1. Bloom pre-filter  — O(1) check of each candidate token against a known-bad
                         fingerprint set (empty by default; seeded with public
                         burned/example tokens). Fast path for known leaks.
  2. Structured regex  — labelled patterns for DB URIs, AKIA keys, sk_live_,
                         PEM headers, .env assignments, etc.
  3. Shannon entropy   — fallback for 40+ char mixed strings the patterns miss.
False-positive guards skip placeholders (``<password>``, ``your_key``,
``.env.example`` templates) and pure general-knowledge questions.

Maps to: Rule R-07 | Threat T-07 | MITRE AML.T0024 | OWASP LLM02
Owner: Nikhil (Sneha wrote the Day-1 stub interface)

NOTE on imports: ``RequestContext`` / ``Snapshot`` are referenced only in type
hints, so they stay under ``TYPE_CHECKING`` — this module never imports
``app.identity`` at runtime and therefore does not depend on that package being
present (kept from the original stub on purpose).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from hashlib import blake2b
from typing import Optional, TYPE_CHECKING

from app.pdp.detectors.base import BaseDetector
from app.pdp.decision import Signal, Disposition

if TYPE_CHECKING:
    from app.identity.context import RequestContext
    from app.policy.models import Snapshot


# ── Tuning ─────────────────────────────────────────────────────────────────
_ENTROPY_MIN_LEN = 40      # policy: "40+ characters of mixed alphanumeric"
_ENTROPY_BITS = 3.5        # bits/char; random base64 ~5-6, English words < 3.5
_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+/_\-=]{20,}")

# Values that look like credentials but are obviously templates/placeholders.
_PLACEHOLDER = re.compile(
    r"^(?:<.*>|\{\{?.*\}?\}|x{3,}|\*{3,}|\.{3,}|"
    r"your[_-]?\w*|my[_-]?\w*|some[_-]?\w*|dummy\w*|example\w*|sample\w*|"
    r"placeholder\w*|changeme\w*|redacted\w*|test[_-]?\w*|abc123|password|"
    r"secret|token|key|value|string)$",
    re.IGNORECASE,
)


# ── Structured secret patterns ─────────────────────────────────────────────
# Each entry: (compiled pattern, human label, confidence). Order matters only
# for the label reported; all are STOP.
_STRUCTURED: list[tuple[re.Pattern[str], str, float]] = [
    # DB connection URI with an embedded password: proto://user:pass@host
    (re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql|"
        r"jdbc:[a-z]+)://[^:@\s/]+:[^@\s/]{3,}@[^\s/]+",
        re.IGNORECASE,
    ), "database connection string", 0.97),

    # AWS access key id (and temporary ASIA), plus explicit secret-key assignment
    (re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"),
     "AWS access key", 0.97),
    (re.compile(r"\baws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}\b",
                re.IGNORECASE), "AWS secret access key", 0.97),

    # Common cloud/service API keys
    (re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"), "Stripe secret key", 0.96),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Google API key", 0.95),
    (re.compile(r"\bghp_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{22,}\b"),
     "GitHub token", 0.96),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "Slack token", 0.95),

    # Bearer / JWT
    (re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b"), "Bearer token", 0.85),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
     "JWT", 0.9),

    # PEM private key block
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     "PEM private key", 0.99),

    # .env-style assignment of a sensitive variable to a real (non-placeholder)
    # value. The negative lookahead skips obvious templates.
    (re.compile(
        r"\b(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|API_?KEY|SECRET_?KEY|"
        r"CLIENT_SECRET|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|PASSWORD|PASSWD|PWD)"
        r"\s*[:=]\s*['\"]?"
        r"(?!<|your|my|some|xxx|\*{3}|\.{3}|placeholder|changeme|example|dummy|"
        r"test\b|secret\b|password\b|token\b)"
        r"[^\s'\"]{6,}",
        re.IGNORECASE,
    ), "credential assignment (.env)", 0.9),
]


# ── Bloom filter for known-bad fingerprints ────────────────────────────────
class _BloomFilter:
    """Tiny, dependency-free Bloom filter over token fingerprints.

    Probabilistic set membership: no false negatives, tunable false positives.
    Used only as a fast pre-filter for previously-seen/burned credentials; the
    structured + entropy passes are the real coverage. Empty by default, so it
    never introduces false positives unless explicitly seeded.
    """

    __slots__ = ("_bits", "_size", "_k")

    def __init__(self, size: int = 8192, k: int = 4) -> None:
        self._size = size
        self._k = k
        self._bits = bytearray(size // 8 + 1)

    def _positions(self, item: str):
        h = blake2b(item.encode("utf-8"), digest_size=16).digest()
        h1 = int.from_bytes(h[:8], "big")
        h2 = int.from_bytes(h[8:], "big") | 1  # odd, so it's coprime-ish
        for i in range(self._k):
            yield (h1 + i * h2) % self._size

    def add(self, item: str) -> None:
        for pos in self._positions(item):
            self._bits[pos // 8] |= 1 << (pos % 8)

    def __contains__(self, item: str) -> bool:
        return all(self._bits[pos // 8] & (1 << (pos % 8)) for pos in self._positions(item))


# Seeded with public, non-secret example/burned tokens so the fast path is
# demonstrably exercised. Extend from a threat feed in production.
_KNOWN_BAD = _BloomFilter()
for _seed in (
    "AKIAIOSFODNN7EXAMPLE",  # AWS's own documentation example key
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # AWS doc example secret
):
    _KNOWN_BAD.add(_seed)


# ── Detection helpers (pure; no internal deps — unit-testable in isolation) ──
def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _looks_like_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.match(value.strip().strip("'\"")))


def find_secret(prompt: str) -> Optional[tuple[str, float]]:
    """Return ``(secret_type, confidence)`` for the first secret found, else None.

    Pure function (no RequestContext/Snapshot needed) so it is trivially unit
    testable and reusable. The class method below adds the audit Signal wrapper.
    """
    if not prompt:
        return None

    # ``.env.example`` templates are legitimate — don't treat their values as live.
    is_template = bool(re.search(r"\.env\.(?:example|sample|template|dist)\b", prompt, re.I))

    # 1) Bloom fast-path over candidate tokens (known-bad / burned creds).
    for token in _ENTROPY_CANDIDATE.findall(prompt):
        if token in _KNOWN_BAD:
            return ("known-compromised credential", 0.99)

    # 2) Structured patterns.
    for pattern, label, conf in _STRUCTURED:
        m = pattern.search(prompt)
        if not m:
            continue
        if is_template and label == "credential assignment (.env)":
            continue
        # DB URIs: skip when the password component is an obvious placeholder
        # (e.g. postgres://user:<password>@host from documentation).
        if label == "database connection string":
            pw = _uri_password(m.group(0))
            if pw and _looks_like_placeholder(pw):
                continue
        # For assignment-style hits, re-check the captured value isn't a placeholder.
        if _placeholder_hit(m.group(0)):
            continue
        return (label, conf)

    # 3) Entropy fallback: long, mixed, high-entropy tokens.
    for token in _ENTROPY_CANDIDATE.findall(prompt):
        if len(token) < _ENTROPY_MIN_LEN:
            continue
        if _looks_like_placeholder(token):
            continue
        has_alpha = any(c.isalpha() for c in token)
        has_digit = any(c.isdigit() for c in token)
        if not (has_alpha and has_digit):
            continue
        if _shannon_entropy(token) >= _ENTROPY_BITS:
            return ("high-entropy secret-like string", 0.7)

    return None


def _placeholder_hit(fragment: str) -> bool:
    """True if an assignment fragment's value side is an obvious placeholder."""
    m = re.search(r"[:=]\s*(.+)$", fragment)
    return bool(m) and _looks_like_placeholder(m.group(1))


def _uri_password(uri: str) -> str | None:
    """Extract the password component from a ``proto://user:pass@host`` URI."""
    m = re.search(r"://[^:@\s/]+:([^@\s/]+)@", uri)
    return m.group(1) if m else None


# ── Detector class (implements Sneha's BaseDetector contract) ───────────────
class SecretsDetector(BaseDetector):
    """Stage 4: infrastructure credential / secret scanner (Rule R-07)."""

    @property
    def stage_name(self) -> str:
        return "secrets_scanner"

    @property
    def stage_order(self) -> int:
        return 4

    def scan(
        self,
        ctx: "RequestContext",
        prompt: str,
        snapshot: "Snapshot",
    ) -> Optional[Signal]:
        """Return a STOP Signal if a credential is detected, else None.

        Never raises (per BaseDetector contract): any internal error yields None.
        """
        try:
            hit = find_secret(prompt)
        except Exception:
            return None
        if hit is None:
            return None

        secret_type, confidence = hit

        # Actor-aware severity (policy T-07): human paste is HIGH; automated
        # systems / adversary patterns are CRITICAL. We only have role here;
        # the audit layer resolves the full actor_type.
        severity = "HIGH"
        role = getattr(ctx, "role", None)
        if role in {"AutomatedSystem", "Service"}:
            severity = "CRITICAL"

        return Signal(
            detector=self.stage_name,
            rule_id="R-07",
            disposition=Disposition.STOP,
            reason=(
                f"Credential detected: {secret_type}. Reference secrets by vault "
                f"path instead of pasting them; rotate any exposed secret."
            ),
            confidence=confidence,
            metadata={
                "owasp_id": "LLM02",
                "atlas_id": "AML.T0024",
                "severity": severity,
                "secret_type": secret_type,
            },
        )
