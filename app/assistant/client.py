# RYAN-DAY1
"""AssistantClient interface — the contract between the PEP and the BACK AI.

Owner: Ryan.
Gate: Day-1 noon — defines the single method enforcement calls to obtain an
answer. Any implementation (V1 stub or V2 real model) that provides `generate`
satisfies this Protocol structurally; callers depend only on this shape.
"""
from typing import Protocol

from app._compat import RequestContext


class AssistantClient(Protocol):
    """Structural interface every assistant implementation must satisfy."""

    def generate(self, prompt: str, ctx: RequestContext) -> str:
        """Return an answer for `prompt` on behalf of the user described by `ctx`."""
        ...
