from app.pdp.authz.scope import ScopeTrie


def test_owned_service_is_allowed():
    trie = ScopeTrie()
    assert trie.check("org-acme", "dvs-service", ["dvs-service"]) is True


def test_unowned_service_is_blocked():
    trie = ScopeTrie()
    assert trie.check("org-acme", "kyc-engine", ["dvs-service"]) is False


def test_wildcard_allows_any_service():
    trie = ScopeTrie()
    assert trie.check("org-acme", "any-service", ["*"]) is True


def test_empty_owned_services_is_blocked():
    trie = ScopeTrie()
    assert trie.check("org-acme", "dvs-service", []) is False


def test_multiple_owned_services():
    trie = ScopeTrie()
    assert trie.check("org-acme", "payment-service", ["dvs-service", "payment-service"]) is True


def test_service_not_in_multi_list_blocked():
    trie = ScopeTrie()
    assert trie.check("org-acme", "kyc-engine", ["dvs-service", "payment-service"]) is False
