from typing import List

# --- TEAM INTEGRATION POINTS ---
# Samarth: instantiate ScopeTrie inside the PolicySnapshot (policy/store.py)
#          — build it once at snapshot load time; pass snapshot into pipeline stages
# Ryan:    extract the target service name from the request body and pass it to check()
#          — the service field must match what's in ctx.owned_services
# Day 2 (Anamika): replace owned_services list check with real trie prefix walk
#          — insert paths like "org-acme/dvs-service/read" and match on prefix


class TrieNode:
    def __init__(self) -> None:
        self.children: dict = {}
        self.is_end: bool = False


class ScopeTrie:
    """Tenant/service boundary checker. Day 1: stub returning ownership match.
    Day 2: will build full prefix trie from org/tenant/resource paths."""

    def __init__(self) -> None:
        self.root = TrieNode()

    def insert(self, path: str) -> None:
        node = self.root
        for part in path.split("/"):
            if part not in node.children:
                node.children[part] = TrieNode()
            node = node.children[part]
        node.is_end = True

    def check(self, tenant: str, service: str, owned_services: List[str]) -> bool:
        """Returns True if the user is allowed to access the service within tenant."""
        if "*" in owned_services:
            return True
        return service in owned_services
