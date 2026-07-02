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


settings = Settings()
