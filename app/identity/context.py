from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- TEAM INTEGRATION POINTS ---
# Samarth: import RequestContext in app/pdp/decision.py and app/pdp/pipeline.py
#          — pipeline.evaluate(ctx, prompt) takes this as first argument
# Ryan:    import RequestContext in app/pep/ingress.py
#          — build this from the incoming HTTP request before calling PDP
# Sneha:   your detectors receive ctx in scan(ctx, prompt, snap)
#          — use ctx.role to skip checks that don't apply to the role

@dataclass
class RequestContext:
    user_id: str
    role: str
    tenant: str
    owned_services: List[str]
    session_token: str
    timestamp: datetime = field(default_factory=_now)
