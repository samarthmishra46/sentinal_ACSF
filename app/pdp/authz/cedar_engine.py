from typing import List, Optional
from app.identity.context import RequestContext
from app.pdp.authz.rbac import has_capability, CODE_HELP, DOC, ARCH, REVIEW_SEC, REVIEW_COMP
from app.pdp.authz.scope import ScopeTrie

# --- TEAM INTEGRATION POINTS ---
# Sneha (Day 2 ✅): policies/v1/authz.cedar with Cedar rules R1-R5 — ready in devlop.
#                   Activate _cedar_sdk_evaluate() once the cedar Python package is installed.
# Samarth (Day 3 ✅): wired evaluate(ctx, action) as Stage 3 in factory.py/pipeline.
#                     Day 4: replace hardcoded action="chat" with get_default_action(ctx)
#                     to fix RT-02 (ComplianceOfficer SMR) and RT-12 (expected ALLOW).
#                     Also pass resource_tenant= from the request so R5 tenant check fires.
# Ryan: STOP → block before AI; ESCALATE → escalation queue (enforcement.py handles both).

# Maps each action to the capability bit it requires (mirrors Sneha's authz.cedar rules)
_ACTION_CAPABILITY = {
    "chat":               CODE_HELP,
    "code_review":        CODE_HELP,
    "doc_access":         DOC,
    "arch_view":          ARCH,
    "security_review":    REVIEW_SEC,
    "compliance_review":  REVIEW_COMP,
}

# Roles that are always blocked regardless of action (safety net)
_BLOCKED_ROLES: set[str] = set()

# Known valid roles
_KNOWN_ROLES = {"Engineer", "Support", "SecurityReviewer", "ComplianceOfficer"}

# Day 4: role → most appropriate DEFAULT action for general requests.
# Samarth: replace action="chat" in _authz_stage with get_default_action(ctx).
# Each role maps to the action that matches their primary RBAC capability,
# so ComplianceOfficer/Support are never blocked at Stage 3 for non-code tasks.
_ROLE_DEFAULT_ACTION: dict[str, str] = {
    "Engineer":          "chat",              # CODE_HELP is their primary capability
    "Support":           "doc_access",         # DOC only — chat would STOP them
    "SecurityReviewer":  "chat",              # CODE_HELP + REVIEW_SEC, chat permitted
    "ComplianceOfficer": "compliance_review",  # REVIEW_COMP, not CODE_HELP
}


def get_default_action(ctx: RequestContext) -> str:
    """Return the correct default action for this role when no specific action is known.

    Samarth: in _authz_stage replace:
        cedar_evaluate(ctx, action="chat")
    with:
        cedar_evaluate(ctx, action=get_default_action(ctx), prompt=prompt,
                       known_orgs=known_orgs, service=service,
                       resource_tenant=resource_tenant)

    This fixes RT-02 (ComplianceOfficer SMR — detector at Stage 7 was never
    reached because Stage 3 STOP'd on action="chat") and RT-12 (expected ALLOW).
    """
    return _ROLE_DEFAULT_ACTION.get(ctx.role, "chat")


def _cedar_sdk_evaluate(ctx: RequestContext, action: str) -> Optional[str]:
    """Placeholder for real Cedar SDK evaluation.

    Sneha: once policies/v1/authz.cedar is ready, implement this:
        from cedar import PolicySet, Request, Entity
        POLICY_PATH = Path(__file__).parents[4] / "policies/v1/authz.cedar"
        _policy_set = PolicySet.from_file(str(POLICY_PATH))
        principal = Entity("User", ctx.user_id, {"role": ctx.role, "tenant": ctx.tenant})
        action_entity = Entity("Action", action)
        resource = Entity("Resource", "assistant")
        result = _policy_set.is_authorized(Request(principal, action_entity, resource))
        return "ALLOW" if result.is_allowed() else "STOP"

    Returns None until cedar package installed — falls through to Python rules.
    """
    return None


def evaluate(
    ctx: RequestContext,
    action: str = "chat",
    prompt: str = "",
    known_orgs: Optional[List[str]] = None,
    service: str = "",
    resource_tenant: str = "",
) -> str:
    """Evaluate whether this context is authorized to perform the action.

    Day 2: Python Cedar-equivalent RBAC bitmask rules.
    Day 3: ESCALATE for R-08 cross-org + unowned service. Backward-compatible.
    Day 4: R5 tenant boundary enforcement (STOP for cross-tenant, SecurityReviewer
           exempt). get_default_action() helper for Samarth to fix action mapping.

    Returns one of: ALLOW | ESCALATE | STOP
    """
    # Rule 0: completely unknown/blocked role → immediate STOP
    if ctx.role in _BLOCKED_ROLES or ctx.role not in _KNOWN_ROLES:
        return "STOP"

    # Try real Cedar SDK first — no-op until cedar package installed
    cedar_result = _cedar_sdk_evaluate(ctx, action)
    if cedar_result is not None:
        return cedar_result

    # Python Cedar-equivalent: check action requires a capability this role has
    required_cap = _ACTION_CAPABILITY.get(action, CODE_HELP)
    if not has_capability(ctx.role, required_cap):
        return "STOP"

    # R5: tenant boundary enforcement — mirrors Cedar authz.cedar forbid rule.
    # Cross-tenant access is a hard STOP. SecurityReviewer exempt for investigations.
    # Samarth: pass resource_tenant= extracted from the request body via Ryan's ingress.
    if resource_tenant and resource_tenant != ctx.tenant:
        if ctx.role != "SecurityReviewer":
            return "STOP"

    # R-08: cross-org prompt detection → ESCALATE for human review
    if prompt and ScopeTrie.detect_cross_org(ctx.tenant, prompt, known_orgs):
        return "ESCALATE"

    # Service ownership: user accessing a service outside their scope → ESCALATE
    if service:
        owned = ctx.owned_services
        if "*" not in owned and service not in owned:
            return "ESCALATE"

    return "ALLOW"
