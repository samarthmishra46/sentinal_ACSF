from app.identity.context import RequestContext

# Day 1 stub: returns "ALLOW" for any known role, "STOP" for unknown.
# Day 2: loads policies/v1/authz.cedar and evaluates real Cedar policies.

# --- TEAM INTEGRATION POINTS ---
# Samarth: wire evaluate() as Stage 2 in app/pdp/pipeline.py
#          — call evaluate(ctx, action) and wrap result into a Signal/Decision
# Sneha:   write the Cedar policy rules in policies/v1/authz.cedar
#          — Day 2 this stub will be replaced with real Cedar evaluation against her policy file
# Ryan:    PEP enforcement (app/pep/enforcement.py) acts on the Decision produced here
#          — if evaluate() returns STOP, enforcement must block before forwarding to AI

_KNOWN_ROLES = {"Engineer", "Support", "SecurityReviewer", "ComplianceOfficer"}


def evaluate(ctx: RequestContext, action: str = "chat") -> str:
    """Evaluate authorization for the given context and action.

    Returns one of: ALLOW | STOP
    """
    if ctx.role in _KNOWN_ROLES:
        return "ALLOW"
    return "STOP"
