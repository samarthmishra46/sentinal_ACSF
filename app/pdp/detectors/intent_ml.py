"""Domain-intent classifier — Stage-8 semantic detector for compliance attacks.

The rules at stage 7 (intent_compliance_scanner) phrase-match: they catch
"skip the CDD check" but miss "disregard the identity step" or a hypothetical
framing. Our Phase-0 eval showed compliance-bypass paraphrases detected at ~8%.
This detector closes that: a logistic regression over the shared MiniLM embedding,
trained (offline) on data generated from the policy catalog itself.

Why this shape:
  * It reuses the embedding the kNN tier already computed for this prompt (LRU
    cache in app/pdp/knn/embed), so it costs ~one matmul, not a second model.
  * It ships as JSON coefficients (models/intent_clf.json) — no sklearn, no torch
    at runtime, no pickle. Runtime is numpy: softmax(W·x + b).
  * It emits the predicted rule's own id, so policy_for() resolves the policy and
    the audit trail keeps its regulatory citation. Disposition follows the rule's
    native catalog level (R-05 bulk → ESCALATE; R-02/03/09 → STOP), gated by the
    model's confidence.

Opt-in and self-guarding: with INTENT_ML_ENABLED false (default) or the model /
embedding unavailable, scan() returns None without loading anything. Never raises.

Owner: Samarth
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from app.config import settings
from app.identity.context import RequestContext
from app.pdp.decision import Disposition, Signal
from app.pdp.detectors.base import BaseDetector
from app.policy.models import Snapshot, policy_for

logger = logging.getLogger(__name__)

_UNSET = object()
_model: object = _UNSET  # dict(labels, weights, intercepts, ...) or None


def _load_model() -> Optional[dict]:
    """Load the JSON classifier once; None if disabled/missing. Never raises."""
    global _model
    if _model is not _UNSET:
        return _model
    try:
        import numpy as np
        raw = json.loads(open(settings.INTENT_MODEL_PATH, encoding="utf-8").read())
        raw["_W"] = np.asarray(raw["weights"], dtype=np.float32)      # (C, D)
        raw["_b"] = np.asarray(raw["intercepts"], dtype=np.float32)   # (C,)
        _model = raw
        logger.info("Intent classifier loaded: %s labels, model %s",
                    len(raw["labels"]), settings.INTENT_MODEL_PATH)
    except Exception as exc:  # missing file, bad JSON, numpy absent
        logger.warning("Intent classifier unavailable (%r); stage disabled", exc)
        _model = None
    return _model


def _predict(prompt: str) -> Optional[tuple[str, float]]:
    """Return (label, probability) for the top class, or None if unavailable.

    Isolated so tests can monkeypatch it without an embedding model.
    """
    model = _load_model()
    if model is None:
        return None
    from app.pdp.knn.embed import embed
    vec = embed(prompt)          # shared, cached — same vector the kNN tier used
    if vec is None:
        return None
    import numpy as np
    logits = model["_W"] @ vec + model["_b"]
    logits -= logits.max()       # numerical stability
    probs = np.exp(logits)
    probs /= probs.sum()
    idx = int(np.argmax(probs))
    return model["labels"][idx], float(probs[idx])


def intent_ml_available() -> bool:
    """True if the classifier loaded — for /health reporting."""
    return settings.INTENT_ML_ENABLED and _load_model() is not None


class IntentMLDetector(BaseDetector):
    """Stage 8: learned compliance-intent classifier. Opt-in, self-guarding."""

    @property
    def stage_name(self) -> str:
        return "intent_ml_scanner"

    @property
    def stage_order(self) -> int:
        return 8  # semantic band, alongside the kNN/injection cascade

    def scan(self, ctx: RequestContext, prompt: str, snap: Snapshot) -> Signal | None:
        try:
            return self._detect(prompt, snap)
        except Exception:  # never raise (BaseDetector contract)
            return None

    def _detect(self, prompt: str, snap: Snapshot | None) -> Signal | None:
        if not settings.INTENT_ML_ENABLED:
            return None
        pred = _predict(prompt)
        if pred is None:
            return None
        label, prob = pred

        if label == "benign" or prob < settings.INTENT_ESCALATE_THRESHOLD:
            return None

        native = _native_disposition(snap, label)
        if prob >= settings.INTENT_STOP_THRESHOLD:
            disposition = native                      # confident → the rule's own level
        else:
            # Lower confidence → soften to ESCALATE (human review) rather than STOP,
            # but never exceed the rule's native level.
            disposition = min(Disposition.ESCALATE, native)

        verb = "blocked" if disposition is Disposition.STOP else "flagged for review"
        return Signal(
            detector=self.stage_name,
            rule_id=label,                            # predicted rule → policy_for resolves
            disposition=disposition,
            reason=(
                f"Domain-intent classifier {verb} this prompt: predicted {label} "
                f"(confidence {prob:.2f})."
            ),
            confidence=round(prob, 4),
            metadata={
                "severity": "HIGH",
                "source": "intent_ml",
                "predicted_label": label,
                "probability": round(prob, 4),
                "stop_threshold": settings.INTENT_STOP_THRESHOLD,
                "escalate_threshold": settings.INTENT_ESCALATE_THRESHOLD,
            },
        )


def _native_disposition(snap: Snapshot | None, rule_id: str) -> Disposition:
    """The rule's catalog disposition (R-05 → ESCALATE, others → STOP). Default STOP."""
    if snap is None:
        return Disposition.STOP
    meta = policy_for(snap, rule_id)
    if not meta:
        return Disposition.STOP
    return Disposition.__members__.get(
        str(meta.get("disposition", "STOP")).upper(), Disposition.STOP)
