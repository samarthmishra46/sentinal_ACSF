from typing import Optional
from app.identity.context import RequestContext
from app.pdp.authz.rbac import has_capability, CODE_HELP, DOC, ARCH, REVIEW_SEC, REVIEW_COMP

# --- TEAM INTEGRATION POINTS ---
# Sneha (Day 2): write policies/v1/authz.cedar with Cedar rules for R1-R5
#                A placeholder with the expected Cedar syntax is in policies/v1/authz.cedar
#                Once written, uncomment _cedar_sdk_evaluate() and it will take over
# Samarth: wire evaluate(ctx, action) as Stage 2 in app/pdp/pipeline.py
#          wrap the return value into a Signal using decision.py models:
#          Signal(rule_id="R-auth", disposition=Disposition[result], confidence=1.0)
# Ryan: PEP enforcement (app/pep/enforcement.py) reads the Decision produced here
#       STOP → block request before forwarding to AI; ESCALATE → queue for review

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

    Returns None until authz.cedar exists — falls through to Python rules.
    """
    return None


def evaluate(ctx: RequestContext, action: str = "chat") -> str:
    """Evaluate whether this context is authorized to perform the action.

    Day 2: Python Cedar-equivalent rules using RBAC bitmask.
    Day 3: delegates to _cedar_sdk_evaluate() once Sneha's authz.cedar is ready.

    Returns one of: ALLOW | STOP
    """
    # Rule 0: completely unknown/blocked role → immediate STOP
    if ctx.role in _BLOCKED_ROLES or ctx.role not in _KNOWN_ROLES:
        return "STOP"

    # Try real Cedar SDK first — no-op until Sneha writes authz.cedar
    cedar_result = _cedar_sdk_evaluate(ctx, action)
    if cedar_result is not None:
        return cedar_result

    # Python Cedar-equivalent: check action requires a capability this role has
    required_cap = _ACTION_CAPABILITY.get(action, CODE_HELP)
    if not has_capability(ctx.role, required_cap):
        return "STOP"

    return "ALLOW"
