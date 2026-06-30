# RYAN-DAY1
"""Placeholder for Anamika's app/identity/context.py — RequestContext.

Owner: Ryan (temporary compile-time placeholder only).
Gate: Day-1 noon — lets the PEP build a RequestContext and pass it through the
stub pipeline before Anamika commits the real identity model. Delete on swap.
"""
# PLACEHOLDER — to be deleted when Anamika commits identity/context.py
from dataclasses import dataclass


@dataclass
class RequestContext:
    user_id: str
    role: str
    tenant: str
    owned_services: list[str]
    session_token: str
    timestamp: str
