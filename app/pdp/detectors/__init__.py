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

ALL_DETECTORS = [
    SecretsDetector(),     # Stage 4
    InjectionDetector(),   # Stage 5
    PIIDetector(),         # Stage 6
    IntentScanner(),       # Stage 7
]

__all__ = [
    "BaseDetector",
    "SecretsDetector",
    "InjectionDetector",
    "PIIDetector",
    "IntentScanner",
    "ALL_DETECTORS",
]