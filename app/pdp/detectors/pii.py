"""PII detector — catches Australian PII before it reaches the model.

Two-pass design keeps the ALLOW path fast:
  Pass 1 (regex): cheap format scan for TFN, passport, Medicare, licence,
                   DOB+name, address+state. If nothing matches, return None
                   in <1ms. Presidio never loads.
  Pass 2 (Presidio NLP): runs ONLY when Pass 1 fires. Confirms the hit with
                          spaCy NER. Boosts confidence and refines entity type.

Rule R-01 | Stage 6 | MITRE AML.T0024 | OWASP LLM02

Owner: Sneha
Stack: presidio-analyzer 2.2.x, spacy 3.7.x, en_core_web_lg
"""

from __future__ import annotations

import re

from app.pdp.detectors.base import BaseDetector
from app.pdp.decision import Signal, Disposition
from app.identity.context import RequestContext
from app.policy.models import Snapshot


# ── Pass 1: regex pre-filters ──────────────────────────────────────────────

_TFN = re.compile(
    r"\b\d{3}[-.\s]\d{3}[-.\s]\d{3}\b"
    r"|\bTFN\s*[:=]?\s*\d{9}\b",
    re.IGNORECASE,
)

_PASSPORT = re.compile(r"\b[A-Z]{1,2}\d{7}\b")

_MEDICARE = re.compile(
    r"\b\d{4}\s?\d{5}\s?\d{1,2}\b"
    r"|\bMedicare\s*(?:number|no|#|:)\s*\d{10,11}\b",
    re.IGNORECASE,
)

_LICENCE = re.compile(
    r"(?:driver'?s?\s*licen[cs]e|DL)\s*(?:number|no|#|:)?\s*[A-Z0-9]{6,10}",
    re.IGNORECASE,
)

_DOB_NEAR_NAME = re.compile(
    r"[A-Z][a-z]+\s+[A-Z][a-z]+.{0,80}"
    r"(?:DOB|date\s*of\s*birth|\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})",
    re.DOTALL,
)

_ADDRESS_AU = re.compile(
    r"\b\d{1,5}\s+[A-Z][a-z]+\s+"
    r"(?:St(?:reet)?|Rd|Road|Ave(?:nue)?|Dr(?:ive)?|Cres|Ct|Pl(?:ace)?|Lane|Ln)\b"
    r".{0,40}\b(?:NSW|VIC|QLD|SA|WA|TAS|NT|ACT)\b",
    re.IGNORECASE,
)

_ALL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_TFN, "TFN"),
    (_PASSPORT, "Passport number"),
    (_MEDICARE, "Medicare number"),
    (_LICENCE, "Driver's licence"),
    (_DOB_NEAR_NAME, "Name + DOB co-occurrence"),
    (_ADDRESS_AU, "Residential address"),
]


# ── Pass 2: Presidio NLP (lazy-loaded) ─────────────────────────────────────

_analyzer = None


def _get_analyzer():  # noqa: ANN202
    """Lazy-load Presidio so the ALLOW path never pays the import cost."""
    global _analyzer  # noqa: PLW0603
    if _analyzer is None:
        try:
            from presidio_analyzer import AnalyzerEngine

            _analyzer = AnalyzerEngine()
        except ImportError:
            _analyzer = "unavailable"
    return _analyzer


def _presidio_confirm(text: str) -> float:
    """Run Presidio as second-pass confirmation, return best confidence score."""
    analyzer = _get_analyzer()
    if analyzer == "unavailable":
        return 0.0
    results = analyzer.analyze(
        text=text,
        language="en",
        entities=["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "LOCATION", "DATE_TIME"],
        score_threshold=0.4,
    )
    return max((r.score for r in results), default=0.0)


# ── Detector class ─────────────────────────────────────────────────────────


class PIIDetector(BaseDetector):
    """Stage 6: Australian PII detection with regex pre-filter + Presidio NLP."""

    @property
    def stage_name(self) -> str:
        return "pii_detector"

    @property
    def stage_order(self) -> int:
        return 6

    def scan(self, ctx: RequestContext, prompt: str, snap: Snapshot) -> Signal | None:
        """Scan for PII. Fast regex first, expensive NLP only when regex fires."""
        try:
            return self._detect(ctx, prompt)
        except Exception:
            return None

    def _detect(self, ctx: RequestContext, prompt: str) -> Signal | None:
        """Internal detection logic separated for clean error handling."""
        # Pass 1: regex
        matched_type: str | None = None
        for pattern, entity_type in _ALL_PATTERNS:
            if pattern.search(prompt):
                matched_type = entity_type
                break

        if matched_type is None:
            return None

        # Pass 2: Presidio confirmation (boosts confidence if available)
        presidio_score = _presidio_confirm(prompt)
        confidence = max(0.85, presidio_score)

        # Actor-aware severity
        severity = "HIGH"
        if ctx.role == "Engineer":
            severity = "LOW"

        return Signal(
            detector=self.stage_name,
            rule_id="R-01",
            disposition=Disposition.STOP,
            reason=f"Customer PII detected: {matched_type}. Use synthetic data for testing.",
            confidence=confidence,
            metadata={
                "owasp_id": "LLM02",
                "atlas_id": "AML.T0024",
                "severity": severity,
                "matched_entity": matched_type,
            },
        )