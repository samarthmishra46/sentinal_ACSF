"""
Sentinel PDP Detectors

All detectors implement BaseDetector and plug into the pipeline.
Stages run in order: 4 -> 5 -> 6 -> 7 (after Cedar auth at 1-3).
"""

from app.pdp.detectors.base import BaseDetector
from app.pdp.detectors.secrets import SecretsDetector
from app.pdp.detectors.injection import InjectionDetector
from app.pdp.detectors.pii import PIIDetector
from app.pdp.detectors.intent import IntentScanner
from app.pdp.detectors.injection_ml import MLInjectionDetector
from app.pdp.detectors.intent_ml import IntentMLDetector
from app.pdp.detectors.destructive_ops import DestructiveOpsDetector

ALL_DETECTORS = [
    SecretsDetector(),          # Stage 4
    InjectionDetector(),        # Stage 5
    PIIDetector(),              # Stage 6
    IntentScanner(),            # Stage 7
    MLInjectionDetector(),      # Stage 8 (opt-in; kNN+DeBERTa cascade, injection)
    IntentMLDetector(),         # Stage 8 (opt-in; compliance-intent classifier)
    DestructiveOpsDetector(),   # Stage 9 (destructive data ops -> ESCALATE)
]

__all__ = [
    "BaseDetector",
    "SecretsDetector",
    "InjectionDetector",
    "PIIDetector",
    "IntentScanner",
    "MLInjectionDetector",
    "IntentMLDetector",
    "DestructiveOpsDetector",
    "ALL_DETECTORS",
]