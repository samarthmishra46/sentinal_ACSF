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

# Anamika's real identity model (app/identity/context.py). This replaced the
# Day-1 placeholder once anamika-auth-day1 landed the identity package; the swap
# was a single line here, exactly as the indirection was designed for.
from app.identity.context import RequestContext

__all__ = ["Decision", "Signal", "Disposition", "RequestContext"]
