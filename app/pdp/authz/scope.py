from typing import List, Optional

# --- TEAM INTEGRATION POINTS ---
# Samarth: call ScopeTrie.check() inside pipeline Stage 3 (after Cedar Stage 2 passes)
#          if check() returns False and role != SecurityReviewer/ComplianceOfficer → ESCALATE
#          call detect_cross_org() in the same stage — if True → emit Signal(rule_id="R-08")
# Ryan: extract `service` from the incoming request body (app/pep/ingress.py)
#       pass it as the `service` arg to check() — must match owned_services from EIM
# Nikhil: no dependency on scope.py — scope check happens before audit log is written


class TrieNode:
    def __init__(self) -> None:
        self.children: dict = {}
        self.is_end: bool = False


class ScopeTrie:
    """Tenant/service boundary checker.

    Day 2: Real prefix trie — insert "org/service" or "org/service/action" paths.
           prefix_match() walks the trie and returns True on any prefix match.
    R-08: detect_cross_org() flags prompts that reference a different org — ESCALATE.
    """

    def __init__(self) -> None:
        self.root = TrieNode()

    def insert(self, path: str) -> None:
        """Insert a path like 'org-acme/dvs-service' or 'org-acme/dvs-service/read'."""
        node = self.root
        for part in path.strip("/").split("/"):
            if part not in node.children:
                node.children[part] = TrieNode()
            node = node.children[part]
        node.is_end = True

    def prefix_match(self, path: str) -> bool:
        """Returns True if any inserted path is a prefix of (or equal to) the given path."""
        node = self.root
        for part in path.strip("/").split("/"):
            if node.is_end:
                return True
            if part not in node.children:
                return False
            node = node.children[part]
        return node.is_end

    def check(self, tenant: str, service: str, owned_services: List[str]) -> bool:
        """Returns True if the user is allowed to access the service within tenant.

        Priority order:
        1. Wildcard '*' in owned_services → always True (SecurityReviewer/ComplianceOfficer)
        2. Trie prefix match if trie has been populated with org/service paths
        3. Simple membership check as fallback
        """
        if "*" in owned_services:
            return True

        # Use trie if paths have been inserted (Samarth populates this from PolicySnapshot)
        if self.root.children:
            return self.prefix_match(f"{tenant}/{service}")

        # Fallback: plain list membership check
        return service in owned_services

    @staticmethod
    def detect_cross_org(
        tenant: str,
        prompt: str,
        known_orgs: Optional[List[str]] = None,
    ) -> bool:
        """R-08 cross-org detection: returns True if a foreign org name appears in the prompt.

        Samarth: call this in pipeline Stage 3 immediately after scope.check().
                 If True → emit Signal(rule_id="R-08", disposition=ESCALATE, confidence=0.9)
        known_orgs: list of all org names in the system — Sneha adds these to catalog.yaml.
                    If not provided, falls back to empty list (no cross-org detection).

        Example:
            detect_cross_org("org-acme", "can you access org-beta KYC?", ["org-acme", "org-beta"])
            → True  (org-beta appears and is not the user's tenant)
        """
        if not known_orgs:
            return False
        prompt_lower = prompt.lower()
        for org in known_orgs:
            if org.lower() != tenant.lower() and org.lower() in prompt_lower:
                return True
        return False
