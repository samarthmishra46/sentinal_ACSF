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
#          — audit_hook.py: replace hardcoded "A-01" with ctx.actor_type
# Sneha:   your detectors receive ctx in scan(ctx, prompt, snap)
#          — use ctx.role to skip checks that don't apply to the role

# Actor type codes — mirrors Nikhil's AuditRecord.actor_type controlled vocabulary
# A-01: Engineer (code/debug/arch)   A-02: Support (basic queries)
# A-03: SecurityReviewer (escalation review)  A-04: ComplianceOfficer (policy/compliance)
_ROLE_ACTOR_TYPE: dict[str, str] = {
    "Engineer":          "A-01",
    "Support":           "A-02",
    "SecurityReviewer":  "A-03",
    "ComplianceOfficer": "A-04",
}


@dataclass
class RequestContext:
    user_id: str
    role: str
    tenant: str
    owned_services: List[str]
    session_token: str
    timestamp: datetime = field(default_factory=_now)
    # Derived from role via EIM; defaults to A-01 for backward compatibility
    # with tests that construct RequestContext directly without specifying actor_type.
    actor_type: str = "A-01"
