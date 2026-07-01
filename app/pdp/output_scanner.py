# RYAN-DAY2
"""Output pipeline — the post-model gate that scans the assistant's *response*
before it ever reaches the user.

Owner: Ryan (Infrastructure + Output Lead).
Sprint: Day-2 deliverable — ``O1 normalize -> O2 PII leak -> O3 code scan ->
O4 alignment``. A request that passed the pre-model gate (PDP/PEP ingress) can
still produce a leaky or harmful *answer*; this is the second enforcement point,
on the way out. The policy document mandates exactly these post-model controls
(R-01/R-07 PII & secrets, R-03/R-09 compliance-weakening code, R-04 exploit
code, R-06 injection-follow / system-prompt disclosure).

Design:
  * Self-contained and dependency-light so it runs in CI today. Structured PII /
    secret formats are matched with regex (the same formats the policy control
    text enumerates). A heavier NLP pass (Presidio/spaCy) is the documented V2
    upgrade and plugs in behind ``o2_pii_leak`` without touching callers.
  * Each stage returns a list of ``OutputFinding``; ``OutputScanner.scan``
    combines them and returns the single strictest ``OutputVerdict``.
  * Fail-safe: if any stage raises, the scanner BLOCKs (never returns a response
    it could not fully screen) — the egress mirror of the pipeline's fail-closed
    rule.
  * Interop: ``OutputVerdict.to_decision()`` maps a verdict onto Samarth's locked
    ``Decision``/``Signal`` contract so the PEP's STOP path and the audit logger
    cite egress blocks exactly like pre-model blocks.

V1 default action on a leak is BLOCK (drop the answer, return a policy-cited
refusal). REDACT — strip the flagged spans and forward the cleaned answer — is
implemented (:func:`redact`) and unit-tested but kept dormant for V2, matching
the locked input contract where REDACT is not yet a wired disposition.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import IntEnum

from app._compat import Decision, Disposition, Signal


class OutputDisposition(IntEnum):
    """Outcome of the output pipeline, ordered by strictness (higher == stricter).

    Mirrors the input ``Disposition`` ordering so the combiner logic is a plain
    ``max()``. REDACT sits between PASS and BLOCK: it still returns an answer, so
    it is less strict than dropping it outright.
    """

    PASS = 0
    REDACT = 1
    BLOCK = 2


# rule_id -> policy_id, for explainable, policy-cited refusals. The audit logger
# resolves the same mapping from the live snapshot (app.policy.models.policy_for);
# this static map is the user-facing fallback when the catalog is empty in V1.
_RULE_TO_POLICY = {
    "R-01": "P-01",  # customer/tenant PII must not leave the boundary
    "R-07": "P-01",  # secrets / credentials
    "R-03": "P-02",  # compliance-weakening logic
    "R-09": "P-02",  # compliance-record manipulation
    "R-04": "P-03",  # offensive / exploit code
    "R-06": "P-07",  # injected-instruction follow / system-prompt disclosure
}


def policy_id_for(rule_id: str | None) -> str | None:
    """Static rule_id -> policy_id used for user-facing citations in V1."""
    return _RULE_TO_POLICY.get(rule_id) if rule_id else None


@dataclass(frozen=True)
class OutputFinding:
    """One issue found in the assistant's response (egress evidence)."""

    scanner: str                 # e.g. "o2_pii_leak"
    rule_id: str | None          # policy rule cited, e.g. "R-01"
    disposition: OutputDisposition
    reason: str
    spans: tuple[str, ...] = ()  # the offending substrings (for redaction / audit)
    confidence: float = 1.0


@dataclass(frozen=True)
class OutputVerdict:
    """The combined egress verdict the PEP enforces."""

    disposition: OutputDisposition
    reason: str
    findings: tuple[OutputFinding, ...] = ()
    cleaned_text: str | None = None  # populated only on a REDACT verdict (V2)

    @property
    def decisive_finding(self) -> OutputFinding | None:
        """The strictest finding behind this verdict, or None if it PASSed."""
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.disposition)

    def to_decision(self, policy_version: str = "") -> Decision:
        """Map onto Samarth's locked Decision contract for STOP + audit.

        BLOCK -> STOP (input contract has no REDACT yet, so REDACT also maps to
        STOP today — fail-safe). Each finding becomes an audit-grade Signal.
        """
        signals = tuple(
            Signal(
                detector=f"output:{f.scanner}",
                rule_id=f.rule_id,
                disposition=Disposition.STOP,
                reason=f.reason,
                confidence=f.confidence,
                metadata={"stage": "output", "spans": list(f.spans)},
            )
            for f in self.findings
        )
        return Decision(Disposition.STOP, self.reason, signals, policy_version)


# --------------------------------------------------------------------------- #
# O1 — Normalize
# --------------------------------------------------------------------------- #

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)


def o1_normalize(text: str) -> str:
    """O1: produce a canonical view for the keyword-based scanners (O3/O4).

    NFKC-folds unicode look-alikes, strips zero-width characters used to smuggle
    instructions past matchers, lowercases, and collapses whitespace runs. The
    structured scanners (O2 PII/secrets) run on the *raw* text so regex offsets
    and casing stay intact for redaction; only the keyword matchers consume this.
    """
    folded = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return re.sub(r"\s+", " ", folded.lower()).strip()


# --------------------------------------------------------------------------- #
# O2 — PII / secret leak (post-model R-01, R-07 / policy P-01)
# --------------------------------------------------------------------------- #

# Structured Australian PII + credential formats, per the policy control text.
# Separators are *required* on TFN/Medicare to keep false positives off generic
# 9-digit numbers (the policy cites the separated /\d{3}-\d{3}-\d{3}/ form).
_PII_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("R-01", "Australian TFN", r"\b\d{3}[-.\s]\d{3}[-.\s]\d{3}\b"),
    ("R-01", "Medicare number", r"\b\d{4}[-\s]\d{5}[-\s]\d\b"),
    ("R-01", "Australian passport", r"\b[NEPDFAUX]\d{7}\b"),
    ("R-01", "date of birth", r"\b\d{1,2}[/-]\d{1,2}[/-](?:19|20)\d{2}\b"),
)

_SECRET_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("R-07", "AWS access key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("R-07", "PEM private key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("R-07", "Bearer token", r"\bBearer\s+[A-Za-z0-9._\-]{20,}"),
    ("R-07", "connection string w/ password", r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:[^\s:/@]+@[^\s/]+"),
    ("R-07", ".env secret assignment", r"\b(?:DB_PASSWORD|API_KEY|SECRET_KEY|AWS_SECRET_ACCESS_KEY)\s*=\s*\S+"),
)


def o2_pii_leak(raw: str, normalized: str) -> list[OutputFinding]:
    """O2: block responses that leak customer PII or infrastructure secrets.

    Even though the pre-model gate strips most of these from prompts, the AI can
    surface PII/secrets from context or training data; the policy requires the
    post-model scanner to catch them (R-01, R-07 note). V2: add a Presidio NER
    pass for unstructured named-entity PII behind this same function.
    """
    findings: list[OutputFinding] = []
    for rule_id, label, pattern in _PII_PATTERNS:
        hits = re.findall(pattern, raw)
        if hits:
            findings.append(OutputFinding(
                scanner="o2_pii_leak", rule_id=rule_id, disposition=OutputDisposition.BLOCK,
                reason=f"response leaks {label}", spans=tuple(hits),
            ))
    for rule_id, label, pattern in _SECRET_PATTERNS:
        hits = re.findall(pattern, raw, flags=re.IGNORECASE)
        if hits:
            findings.append(OutputFinding(
                scanner="o2_pii_leak", rule_id=rule_id, disposition=OutputDisposition.BLOCK,
                reason=f"response leaks {label}", spans=tuple(hits),
            ))
    return findings


# --------------------------------------------------------------------------- #
# O3 — Code scan (post-model R-03/R-09 compliance-weakening, R-04 exploit)
# --------------------------------------------------------------------------- #

# Compliance-weakening code: functions that wave checks through, commented-out
# controls, hardcoded-safe risk, reporting flags forced off, or SQL that mutates
# audit/compliance records (policy P-02, R-03 & R-09 post-model controls).
_COMPLIANCE_WEAKENING: tuple[tuple[str, str, str], ...] = (
    ("R-03", "validation function hardcoded to pass",
     r"def\s+\w*(?:verify|validate|check|cdd|kyc|aml|compliance)\w*\s*\([^)]*\)\s*:\s*return\s+true"),
    ("R-03", "compliance check commented out",
     r"#.*\b(?:kyc|cdd|aml|compliance|sanction|identity)\b.*\bcheck"),
    ("R-03", "risk score hardcoded to a safe value",
     r"risk(?:_score)?\s*=\s*(?:0|['\"](?:low|safe|none|pass)['\"])"),
    ("R-09", "reporting flag forced off",
     r"\b(?:requires_reporting|smr|report|reportable|flag)\w*\s*=\s*(?:false|0|none)\b"),
    ("R-09", "mutation of an audit/compliance record",
     r"\b(?:update|delete)\b[^;]*\b(?:audit_trail|audit_log|compliance|cdd_record|risk_score|assessment)\b"),
)

# Functional exploit code (policy P-03, R-04 post-model control).
_EXPLOIT_CODE: tuple[tuple[str, str, str], ...] = (
    ("R-04", "SQL injection payload", r"'\s*or\s*'?1'?\s*=\s*'?1|\bunion\s+select\b|or\s+1\s*=\s*1\s*--"),
    ("R-04", "XSS vector", r"<script\b[^>]*>|onerror\s*=\s*['\"]?[^'\"]*alert"),
    ("R-04", "reverse shell", r"bash\s+-i\s*>&\s*/dev/tcp/|nc\s+-e\s|/bin/sh\s+-i"),
)


def o3_code_scan(raw: str, normalized: str) -> list[OutputFinding]:
    """O3: block code in the response that weakens compliance or attacks systems."""
    findings: list[OutputFinding] = []
    for rule_id, label, pattern in (*_COMPLIANCE_WEAKENING, *_EXPLOIT_CODE):
        m = re.search(pattern, normalized)
        if m:
            findings.append(OutputFinding(
                scanner="o3_code_scan", rule_id=rule_id, disposition=OutputDisposition.BLOCK,
                reason=f"response contains {label}", spans=(m.group(0).strip(),),
            ))
    return findings


# --------------------------------------------------------------------------- #
# O4 — Alignment (post-model R-06 injection-follow / system-prompt disclosure)
# --------------------------------------------------------------------------- #

# Signs the AI followed an injected instruction or disclosed its own framing.
# Conservative on purpose — these phrases are vanishingly rare in a legitimate
# compliance answer, so false positives are unlikely.
_ALIGNMENT_MARKERS: tuple[tuple[str, str], ...] = (
    ("system-prompt disclosure", r"\b(?:my|the)\s+system\s+prompt\s+(?:is|says|reads)\b"),
    ("system-prompt disclosure", r"\byou\s+are\s+sentinel\b|\bmy\s+instructions\s+are\b"),
    ("jailbreak persona adopted", r"\b(?:i\s+am\s+now|acting\s+as)\s+dan\b|\bdan\s+mode\s+enabled\b"),
    ("ignored safety instructions", r"\bignoring\s+(?:all\s+)?(?:previous|prior|safety)\s+instructions\b"),
)


def o4_alignment(raw: str, normalized: str) -> list[OutputFinding]:
    """O4: block responses that show the AI was steered off its defined role."""
    findings: list[OutputFinding] = []
    for label, pattern in _ALIGNMENT_MARKERS:
        m = re.search(pattern, normalized)
        if m:
            findings.append(OutputFinding(
                scanner="o4_alignment", rule_id="R-06", disposition=OutputDisposition.BLOCK,
                reason=f"response shows {label}", spans=(m.group(0).strip(),),
            ))
    return findings


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class OutputScanner:
    """Runs O1->O4 against an assistant response and returns one verdict.

    Stateless and cheap; the PEP holds one instance as a module singleton. Swap
    in a Presidio-backed O2 or richer O4 without changing the call site.
    """

    def scan(self, answer: str, prompt: str = "", ctx=None) -> OutputVerdict:
        """Scan ``answer`` and return the strictest egress verdict.

        ``prompt``/``ctx`` are accepted for future context-aware checks (e.g.
        "did the answer disclose data the prompt never asked for") and to keep
        the signature stable; the V1 scanners are response-only.
        """
        try:
            normalized = o1_normalize(answer)              # O1
            findings: list[OutputFinding] = []
            findings += o2_pii_leak(answer, normalized)     # O2
            findings += o3_code_scan(answer, normalized)    # O3
            findings += o4_alignment(answer, normalized)    # O4
        except Exception as exc:  # pragma: no cover - defensive
            # Fail-safe: a scanner that crashes must never let an unscreened
            # answer through. Block and surface it as an infra finding.
            finding = OutputFinding(
                scanner="output", rule_id=None, disposition=OutputDisposition.BLOCK,
                reason=f"output scan failed: {type(exc).__name__}",
            )
            return OutputVerdict(OutputDisposition.BLOCK, finding.reason, (finding,))

        if not findings:
            return OutputVerdict(OutputDisposition.PASS, "no egress leak detected")

        decisive = max(findings, key=lambda f: f.disposition)
        return OutputVerdict(decisive.disposition, decisive.reason, tuple(findings))


def redact(text: str, findings: tuple[OutputFinding, ...]) -> str:
    """Strip every flagged span from ``text``, replacing it with ``[REDACTED]``.

    DORMANT (V2): the input contract has no REDACT disposition yet, so the PEP
    BLOCKs on a leak rather than forwarding a cleaned answer. This implements the
    span-stripping the sprint plan calls for and is unit-tested, ready to wire
    when REDACT is promoted out of V2.
    """
    cleaned = text
    for finding in findings:
        for span in finding.spans:
            cleaned = cleaned.replace(span, "[REDACTED]")
    return cleaned
