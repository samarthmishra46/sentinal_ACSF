"""Application configuration for the Sentinel PEP and audit services."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_URL = f"sqlite:///{ROOT / 'audit.db'}"
DEFAULT_POLICY_BUNDLE_PATH = ROOT / "policies" / "v1"


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {value!r}")


class Settings:
    """Runtime configuration values loaded from environment variables."""

    def __init__(self) -> None:
        self.DB_URL: str = os.getenv("DB_URL", DEFAULT_DB_URL)
        self.LATENCY_BUDGET_MS: int = _env_int("LATENCY_BUDGET_MS", 200)
        self.SLACK_WEBHOOK: Optional[str] = os.getenv("SLACK_WEBHOOK")
        self.POLICY_BUNDLE_PATH: Path = Path(
            os.getenv("POLICY_BUNDLE_PATH", DEFAULT_POLICY_BUNDLE_PATH)
        ).resolve()


settings = Settings()
