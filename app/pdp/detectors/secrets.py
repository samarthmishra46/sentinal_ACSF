"""
Secrets / Credential Detector — Stage 4 (Day 1: stub)

Detects infrastructure secrets pasted into prompts:
  DB connection strings, API keys, Bearer tokens,
  PEM private keys, .env contents, high-entropy strings.

Maps to: Rule R-07 | MITRE AML.T0024 | OWASP LLM02
Day 1: returns None. Day 2 (Nikhil): regex + entropy scanner.

Owner: Nikhil (Sneha writes Day 1 stub interface)
"""

from __future__ import annotations
from typing import Optional, TYPE_CHECKING

from app.pdp.detectors.base import BaseDetector
from app.pdp.decision import Signal

if TYPE_CHECKING:
    from app.identity.context import RequestContext
    from app.policy.models import Snapshot


class SecretsDetector(BaseDetector):

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
        # Day 1 stub — no detection.
        # Day 2 (Nikhil implements):
        #   regex for structured secrets (DB URIs, API key prefixes)
        #   + Shannon entropy for high-entropy strings
        # On match, return:
        #   Signal(
        #       detector=self.stage_name,
        #       rule_id="R-07",
        #       disposition=Disposition.STOP,
        #       reason="Credential detected: {secret_type}.",
        #       confidence=score,
        #       metadata={
        #           "owasp_id": "LLM02",
        #           "atlas_id": "AML.T0024",
        #           "severity": "HIGH",
        #           "secret_type": secret_type,
        #       },
        #   )
        return None