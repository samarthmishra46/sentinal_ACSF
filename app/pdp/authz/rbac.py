from typing import Dict

# --- TEAM INTEGRATION POINTS ---
# Samarth: call has_capability() inside pipeline Stage 3 (after Cedar clears Stage 2)
#          — import CODE_HELP / REVIEW_SEC etc. and check against ctx.role
# Sneha:   your intent detector (intent.py) should call has_capability() to short-circuit
#          — e.g. if role lacks REVIEW_SEC, flag any security-review request as suspicious
# Nikhil:  no direct dependency — ROLE_MASK is auth-layer only, not needed in audit logger

# Capability bitmasks
CODE_HELP   = 0b00001  # Ask about code / architecture help
DOC         = 0b00010  # Access documentation
ARCH        = 0b00100  # Access architecture diagrams
REVIEW_SEC  = 0b01000  # Trigger security review
REVIEW_COMP = 0b10000  # Trigger compliance review

ROLE_MASK: Dict[str, int] = {
    "Engineer":          CODE_HELP | DOC | ARCH,
    "Support":           DOC,
    "SecurityReviewer":  CODE_HELP | DOC | ARCH | REVIEW_SEC,
    "ComplianceOfficer": DOC | REVIEW_COMP,
}


def has_capability(role: str, capability: int) -> bool:
    """O(1) bitmask check — returns True if role has the given capability."""
    return bool(ROLE_MASK.get(role, 0) & capability)
