"""ML injection detector — semantic Stage-8 backstop for R-06 (Samarth · Day-5).

The Stage-5 rule scanner (``injection.py``) is an exact-phrase matcher: fast,
zero false positives, fully cite-able — but blind to paraphrase. Our adversarial
eval showed it catches only ~1/3 of synonym-swapped and homoglyph'd injections.

This detector closes that gap with a small BERT-family encoder classifier
(default: a fine-tuned DeBERTa) that scores *intent* regardless of wording. It
sits at stage_order 8 — after every rule stage — so:

  * cheapest-first is preserved: obvious threats STOP at stages 4-7 and never
    reach the model; it only runs on prompts the rules let through.
  * a model-only hit ESCALATEs by default (routes ambiguity to a human, and
    each review becomes a labelled example); it STOPs only at high confidence.
  * provenance stays intact: it emits rule_id "R-06" (same threat/policy, so the
    audit log's policy lookup still resolves) with the confidence score and the
    model name in metadata — citation *and* the probability.

It is **opt-in and self-guarding**. With ``ML_DETECTOR_ENABLED`` false (the
default) ``scan`` returns None immediately and nothing is imported or loaded, so
the base install stays lightweight and the deterministic red-team gate is
unaffected. When enabled but ``transformers``/``torch``/the model are missing,
it degrades to None rather than raising — mirroring the ahocorasick fallback in
``injection.py``. Enable it with the ``ml`` extra:  pip install -e ".[ml]".

Owner: Samarth   Model: configurable via ML_MODEL_NAME
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from app.config import settings
from app.identity.context import RequestContext
from app.pdp.decision import Disposition, Signal
from app.pdp.detectors.base import BaseDetector
from app.policy.models import Snapshot

logger = logging.getLogger(__name__)

# Loaded once, lazily, on first enabled scan. Sentinels distinguish the three
# states: never-tried (_UNSET), tried-and-failed (None), tried-and-ok (callable).
_UNSET = object()
_classifier: object = _UNSET


def _load_classifier() -> Optional[Callable[[str], list]]:
    """Build the HF text-classification pipeline once; None if unavailable.

    Kept out of module import so importing this file never drags in torch. Any
    failure (missing lib, no network for the model download, incompatible
    version) logs a warning and disables the detector rather than crashing the
    PEP — an ML backstop must never take down the rule engine.
    """
    global _classifier
    if _classifier is not _UNSET:
        return _classifier  # cached (callable or None)
    try:
        from transformers import pipeline  # heavy; imported only when enabled

        clf = pipeline(
            "text-classification",
            model=settings.ML_MODEL_NAME,
            truncation=True,
            max_length=512,
            top_k=None,  # return every label's score
        )
        logger.info("ML injection detector loaded model %s", settings.ML_MODEL_NAME)
        _classifier = clf
    except Exception as exc:  # ImportError, network, model errors — all soft
        logger.warning(
            "ML injection detector unavailable (%s): %r; falling back to rules-only",
            settings.ML_MODEL_NAME, exc,
        )
        _classifier = None
    return _classifier


def _injection_score(prompt: str) -> Optional[float]:
    """Return P(injection) in [0,1] for the prompt, or None if unavailable.

    Isolated so tests can monkeypatch it with a fake scorer (no torch needed).
    """
    clf = _load_classifier()
    if clf is None:
        return None
    scores = clf(prompt)
    # top_k=None yields a list[dict]; batched calls yield list[list[dict]].
    if scores and isinstance(scores[0], list):
        scores = scores[0]
    for entry in scores:
        if "inject" in entry["label"].lower():
            return float(entry["score"])
    # Fallback: no explicit injection label — treat a non-"safe"/"legit" top
    # label as the positive class.
    top = max(scores, key=lambda e: e["score"])
    if top["label"].lower() not in ("safe", "legit", "benign", "label_0"):
        return float(top["score"])
    return 1.0 - float(top["score"])


# --- kNN similarity tier (Phase 2) -----------------------------------------
# Loaded once, lazily, on first enabled scan. Same three-state sentinel pattern.
_bank: object = _UNSET


def _load_bank():
    """Load the attack bank once; None if disabled or unavailable. Never raises."""
    global _bank
    if _bank is not _UNSET:
        return _bank
    try:
        from app.pdp.knn.bank import load_bank
        _bank = load_bank()
    except Exception as exc:  # import error, corrupt bank — soft-disable
        logger.warning("Attack bank unavailable (%r); similarity tier off", exc)
        _bank = None
    return _bank


def _nearest_attack(prompt: str):
    """Return (similarity, BankEntry) for the closest known attack, or None.

    Isolated so tests can monkeypatch it with a fake without an embedding model.
    """
    bank = _load_bank()
    if bank is None:
        return None
    from app.pdp.knn.embed import embed
    vec = embed(prompt)
    if vec is None:
        return None
    return bank.nearest(vec)


def _rule_ceiling(snap: "Snapshot | None", rule_id: str) -> Disposition:
    """The strictest disposition a kNN match to ``rule_id`` may emit.

    Read from the rule's catalog entry: an ESCALATE-class rule (R-05 bulk, R-08
    cross-org) caps a similarity match at ESCALATE even at similarity 1.0. If the
    rule can't be resolved (e.g. no snapshot in a unit test), default to STOP —
    i.e. no cap, preserving the raw similarity verdict.
    """
    if snap is None:
        return Disposition.STOP
    from app.policy.models import policy_for
    meta = policy_for(snap, rule_id)
    if not meta:
        return Disposition.STOP
    name = str(meta.get("disposition", "STOP")).upper()
    return Disposition.__members__.get(name, Disposition.STOP)


def ml_detection_mode() -> str:
    """Report detection status for the /health endpoint.

    'rules-only'            — both semantic tiers disabled (default)
    'rules+knn'             — similarity tier on, classifier off
    'rules+ml'              — classifier on, similarity tier off
    'rules+knn+ml'          — full cascade
    '... (unavailable)'     — a tier is enabled but its model/bank failed to load
    """
    from app.pdp.detectors.intent_ml import intent_ml_available

    knn_on = settings.KNN_ENABLED and _load_bank() is not None
    ml_on = settings.ML_DETECTOR_ENABLED and _load_classifier() is not None
    intent_on = intent_ml_available()
    knn_broken = settings.KNN_ENABLED and _load_bank() is None
    ml_broken = settings.ML_DETECTOR_ENABLED and _load_classifier() is None
    intent_broken = settings.INTENT_ML_ENABLED and not intent_on

    parts = []
    if knn_on:
        parts.append("knn")
    if intent_on:
        parts.append("intent")
    if ml_on:
        parts.append("ml")
    # "rules-only" preserves the V1 /health contract when no semantic tier is live.
    mode = "rules+" + "+".join(parts) if parts else "rules-only"
    broken = [n for n, b in (("knn", knn_broken), ("intent", intent_broken),
                             ("ml", ml_broken)) if b]
    if broken:
        mode += f" ({'/'.join(broken)} unavailable)"
    return mode


class MLInjectionDetector(BaseDetector):
    """Stage 8: semantic injection classifier. Opt-in, self-guarding backstop."""

    @property
    def stage_name(self) -> str:
        return "injection_ml_scanner"

    @property
    def stage_order(self) -> int:
        return 8  # after intent (7): only runs on prompts the rules let through

    def scan(self, ctx: RequestContext, prompt: str, snap: Snapshot) -> Signal | None:
        """Run the semantic cascade; STOP at high confidence, ESCALATE in the middle."""
        try:
            return self._detect(prompt, snap)
        except Exception:  # never raise out of a detector (BaseDetector contract)
            return None

    def _detect(self, prompt: str, snap: Snapshot | None = None) -> Signal | None:
        """Three-tier cascade, cheapest first.

        1. kNN similarity to a known attack (~10ms):
             sim >= KNN_STOP_THRESHOLD → STOP now; the classifier never runs.
             sim <  KNN_BAND_LOW       → not close to anything → no objection.
             in between                → ambiguous; fall through to the classifier.
        2. DeBERTa classifier (~400ms) only on the ambiguous band.

        Keeping the band narrow is what keeps p95 inside budget: most prompts
        resolve at tier 1 for microseconds and never pay the classifier cost.
        """
        knn_hit = self._knn_detect(prompt, snap)
        if knn_hit is not None:
            signal, escalate_to_classifier = knn_hit
            if not escalate_to_classifier:
                return signal  # STOP or clean — decided by similarity alone

        if not settings.ML_DETECTOR_ENABLED:
            # No classifier available; the kNN middle band alone can't decide, so
            # surface an ESCALATE if we were in the band, else nothing.
            return knn_hit[0] if knn_hit else None

        return self._classifier_detect(prompt)

    def _knn_detect(self, prompt: str, snap: Snapshot | None = None):
        """kNN tier. Returns None (tier off), or (Signal|escalate_marker, fall_through).

        - (stop_signal, False)     — very close to a known attack → STOP.
        - (escalate_signal, True)  — in the ambiguous band → prefer classifier, but
                                      the escalate_signal is the fallback if none.
        - (None-ish) handled by returning None so the caller continues.
        """
        if not settings.KNN_ENABLED:
            return None
        nearest = _nearest_attack(prompt)
        if nearest is None:
            return None
        sim, entry = nearest

        # A similarity match to an ESCALATE-class attack (e.g. R-05 bulk, R-08
        # cross-org) must never be escalated to STOP: similarity says "this is that
        # attack", the rule's catalog disposition says how strict that attack is.
        ceiling = _rule_ceiling(snap, entry.rule_id)

        if sim >= settings.KNN_STOP_THRESHOLD:
            disp = min(Disposition.STOP, ceiling)
            return self._knn_signal(sim, entry, disp), False
        if sim >= settings.KNN_BAND_LOW:
            # Ambiguous: fall through to the classifier, but keep an ESCALATE as
            # the fallback verdict if the classifier is unavailable.
            disp = min(Disposition.ESCALATE, ceiling)
            return self._knn_signal(sim, entry, disp), True
        return None  # far from every known attack → this tier has no objection

    def _knn_signal(self, sim: float, entry, disposition: Disposition) -> Signal:
        """Build a Signal from a bank match — cite the matched attack, not a guess."""
        verb = "blocked" if disposition is Disposition.STOP else "flagged for review"
        return Signal(
            detector=self.stage_name,
            rule_id=entry.rule_id,  # inherit the matched attack's rule → policy_for resolves
            disposition=disposition,
            reason=(
                f"Semantic similarity {verb} this prompt: {sim:.2f} similar to "
                f"known attack {entry.id} ({entry.rule_id})."
            ),
            confidence=round(sim, 4),
            metadata={
                "severity": "HIGH",
                "source": "knn",
                "nearest_id": entry.id,
                "nearest_rule": entry.rule_id,
                "similarity": round(sim, 4),
                "stop_threshold": settings.KNN_STOP_THRESHOLD,
                "band_low": settings.KNN_BAND_LOW,
            },
        )

    def _classifier_detect(self, prompt: str) -> Signal | None:
        """DeBERTa tier (the original V1 behaviour), run only on the ambiguous band."""
        score = _injection_score(prompt)
        if score is None:
            return None

        if score >= settings.ML_STOP_THRESHOLD:
            disposition = Disposition.STOP
        elif score >= settings.ML_ESCALATE_THRESHOLD:
            disposition = Disposition.ESCALATE
        else:
            return None

        verb = "blocked" if disposition is Disposition.STOP else "flagged for review"
        return Signal(
            detector=self.stage_name,
            rule_id="R-06",
            disposition=disposition,
            reason=(
                f"Semantic injection classifier {verb} this prompt "
                f"(confidence {score:.2f})."
            ),
            confidence=score,
            metadata={
                "owasp_id": "LLM01",
                "atlas_id": "AML.T0051",
                "severity": "HIGH",
                "model": settings.ML_MODEL_NAME,
                "score": round(score, 4),
                "stop_threshold": settings.ML_STOP_THRESHOLD,
                "escalate_threshold": settings.ML_ESCALATE_THRESHOLD,
                "source": "ml",
            },
        )
