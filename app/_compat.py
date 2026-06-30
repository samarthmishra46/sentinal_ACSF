# RYAN-DAY1
"""Compatibility / indirection layer — the single swap point for shared models.

Owner: Ryan.
Every file in Ryan's PEP imports the shared models from here. Decision/Signal/
Disposition now come from Samarth's LOCKED PDP contract, live in devlop (PR #2).
RequestContext is still a placeholder until Anamika commits
app/identity/context.py — then the swap is the single line below.
"""

# Locked PDP contract (Samarth) — app/pdp/decision.py.
from app.pdp.decision import Decision, Disposition, Signal

# Switch this when Anamika commits app/identity/context.py:
#   from app.identity.context import RequestContext
from app._placeholders.context import RequestContext

__all__ = ["Decision", "Signal", "Disposition", "RequestContext"]
