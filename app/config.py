"""Application configuration for the Sentinel PEP and audit services."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_URL = f"sqlite:///{ROOT / 'audit.db'}"
DEFAULT_POLICY_BUNDLE_PATH = ROOT / "policies" / "v1"

# Known organisation / tenant names in the system. Used by R-08 cross-org
# detection (app/pdp/authz/scope.py::detect_cross_org): a prompt that references
# an org other than the caller's own tenant is flagged for ESCALATE. Override at
# runtime with a comma-separated KNOWN_ORGS env var.
DEFAULT_KNOWN_ORGS = ["org-acme", "org-beta", "firm-alpha", "firm-beta"]


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {value!r}")


def _env_list(name: str, default: list[str]) -> list[str]:
    """Parse a comma-separated env var into a list of trimmed strings."""
    value = os.getenv(name)
    if value is None:
        return list(default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _env_bool(name: str, default: bool) -> bool:
    """Parse a boolean env var (1/true/yes/on, case-insensitive)."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        raise ValueError(f"{name} must be a float, got {value!r}")


class Settings:
    """Runtime configuration values loaded from environment variables."""

    def __init__(self) -> None:
        self.DB_URL: str = os.getenv("DB_URL", DEFAULT_DB_URL)
        self.LATENCY_BUDGET_MS: int = _env_int("LATENCY_BUDGET_MS", 200)
        self.SLACK_WEBHOOK: Optional[str] = os.getenv("SLACK_WEBHOOK")
        self.POLICY_BUNDLE_PATH: Path = Path(
            os.getenv("POLICY_BUNDLE_PATH", DEFAULT_POLICY_BUNDLE_PATH)
        ).resolve()
        self.KNOWN_ORGS: list[str] = _env_list("KNOWN_ORGS", DEFAULT_KNOWN_ORGS)

        # --- ML injection detector (Stage 8) ---------------------------------
        # On by default. Needs the `ml` extra installed; without it the detector
        # self-guards (logs a warning, degrades to rules-only) rather than
        # failing, so a base install still runs. Set ML_DETECTOR_ENABLED=false
        # to keep the pipeline purely deterministic (the deploy image does).
        # Thresholds are tuned from the adversarial eval
        # (tests/eval/adversarial.py): STOP at high confidence, ESCALATE in the
        # ambiguous middle.
        self.ML_DETECTOR_ENABLED: bool = _env_bool("ML_DETECTOR_ENABLED", True)
        self.ML_MODEL_NAME: str = os.getenv(
            "ML_MODEL_NAME", "protectai/deberta-v3-base-prompt-injection-v2"
        )
        self.ML_STOP_THRESHOLD: float = _env_float("ML_STOP_THRESHOLD", 0.9)
        self.ML_ESCALATE_THRESHOLD: float = _env_float("ML_ESCALATE_THRESHOLD", 0.5)

        # --- Semantic layer: shared embedding + kNN attack bank (Stage 8) -----
        # Off by default. When enabled, the injection stage becomes a cascade:
        # a cheap cosine-similarity lookup against a bank of known attacks, and
        # only prompts in the ambiguous middle band fall through to the DeBERTa
        # classifier. Thresholds are placeholders until tools/sweep_thresholds.py
        # tunes them on the Phase-0 corpus. See docs/v2_eval_results.md.
        self.KNN_ENABLED: bool = _env_bool("KNN_ENABLED", False)
        self.KNN_MODEL_NAME: str = os.getenv(
            "KNN_MODEL_NAME", "sentence-transformers/all-MiniLM-L6-v2"
        )
        self.KNN_BANK_PATH: str = os.getenv(
            "KNN_BANK_PATH", str(ROOT / "models" / "attack_bank")
        )
        # Tuned on held-out paraphrases by tools/sweep_thresholds.py:
        # STOP@0.80 → 89.6% guaranteed detection, 0.7% benign false-block, ~7%
        # band load. Band 0.72 routes near-misses to the classifier (which clears
        # benign) rather than hard-blocking them. See docs/v2_eval_results.md.
        self.KNN_STOP_THRESHOLD: float = _env_float("KNN_STOP_THRESHOLD", 0.80)
        self.KNN_BAND_LOW: float = _env_float("KNN_BAND_LOW", 0.72)

        # --- Domain-intent classifier (Stage 8; opt-in) ----------------------
        # Logistic regression over the shared MiniLM embedding, catching the
        # compliance-intent attacks (R-02/03/05/09) the rules phrase-match and
        # miss. Ships as JSON coefficients (models/intent_clf.json); runtime is
        # pure numpy, no sklearn/torch. Reuses the embedding the kNN tier already
        # computed, so it costs ~one matmul. Trained by tools/train_intent.py.
        self.INTENT_ML_ENABLED: bool = _env_bool("INTENT_ML_ENABLED", False)
        self.INTENT_MODEL_PATH: str = os.getenv(
            "INTENT_MODEL_PATH", str(ROOT / "models" / "intent_clf.json")
        )
        self.INTENT_STOP_THRESHOLD: float = _env_float("INTENT_STOP_THRESHOLD", 0.70)
        self.INTENT_ESCALATE_THRESHOLD: float = _env_float("INTENT_ESCALATE_THRESHOLD", 0.45)

        # --- Behavioural / session layer (Stage 10; opt-in) ------------------
        # Session-level anomaly detection — the pattern-over-time the per-prompt
        # detectors are blind to (bulk assembly, off-hours sweeps, probing). Off
        # by default; thresholds are calibrated on synthetic traffic and MUST be
        # re-tuned against real usage. Rule R-22 / policy P-22. Anomaly → ESCALATE.
        self.BEHAVIOUR_ENABLED: bool = _env_bool("BEHAVIOUR_ENABLED", False)
        self.BEHAVIOUR_MAX_QUERIES_PER_HOUR: int = _env_int("BEHAVIOUR_MAX_QUERIES_PER_HOUR", 60)
        self.BEHAVIOUR_MAX_DISTINCT_CUSTOMERS: int = _env_int("BEHAVIOUR_MAX_DISTINCT_CUSTOMERS", 25)
        self.BEHAVIOUR_MAX_OFF_OWNED_PER_HOUR: int = _env_int("BEHAVIOUR_MAX_OFF_OWNED_PER_HOUR", 15)
        self.BEHAVIOUR_MAX_ESCALATE_STREAK: int = _env_int("BEHAVIOUR_MAX_ESCALATE_STREAK", 3)


settings = Settings()
