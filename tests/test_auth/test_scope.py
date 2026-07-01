from app.pdp.authz.scope import ScopeTrie


# ── Day 1 stub tests (still valid) ──────────────────────────

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


# ── Day 2 real trie tests ────────────────────────────────────

def test_trie_insert_and_prefix_match():
    trie = ScopeTrie()
    trie.insert("org-acme/dvs-service")
    assert trie.prefix_match("org-acme/dvs-service") is True

def test_trie_prefix_match_deeper_path():
    # Inserted: org-acme/dvs-service → should also match org-acme/dvs-service/read
    trie = ScopeTrie()
    trie.insert("org-acme/dvs-service")
    assert trie.prefix_match("org-acme/dvs-service/read") is True

def test_trie_no_match_different_org():
    trie = ScopeTrie()
    trie.insert("org-acme/dvs-service")
    assert trie.prefix_match("org-beta/dvs-service") is False

def test_trie_no_match_different_service():
    trie = ScopeTrie()
    trie.insert("org-acme/dvs-service")
    assert trie.prefix_match("org-acme/kyc-engine") is False

def test_trie_check_uses_prefix_match_when_populated():
    trie = ScopeTrie()
    trie.insert("org-acme/dvs-service")
    assert trie.check("org-acme", "dvs-service", ["dvs-service"]) is True
    assert trie.check("org-acme", "kyc-engine", ["dvs-service"]) is False

def test_trie_multiple_inserts():
    trie = ScopeTrie()
    trie.insert("org-acme/dvs-service")
    trie.insert("org-acme/payment-service")
    assert trie.prefix_match("org-acme/dvs-service") is True
    assert trie.prefix_match("org-acme/payment-service") is True
    assert trie.prefix_match("org-acme/kyc-engine") is False

def test_trie_wildcard_still_bypasses_trie():
    trie = ScopeTrie()
    trie.insert("org-acme/dvs-service")
    # Wildcard overrides trie — SecurityReviewer/ComplianceOfficer use this
    assert trie.check("org-acme", "kyc-engine", ["*"]) is True


# ── Day 2 R-08 cross-org detection tests ────────────────────

def test_cross_org_not_detected_when_no_orgs():
    assert ScopeTrie.detect_cross_org("org-acme", "help me with DVS", []) is False

def test_cross_org_not_detected_same_org():
    assert ScopeTrie.detect_cross_org(
        "org-acme", "help with org-acme DVS", ["org-acme", "org-beta"]
    ) is False

def test_cross_org_detected_foreign_org_in_prompt():
    # R-08: user from org-acme mentions org-beta in prompt → ESCALATE
    assert ScopeTrie.detect_cross_org(
        "org-acme", "can you access org-beta kyc records?", ["org-acme", "org-beta"]
    ) is True

def test_cross_org_case_insensitive():
    assert ScopeTrie.detect_cross_org(
        "org-acme", "access ORG-BETA records", ["org-acme", "org-beta"]
    ) is True

def test_cross_org_no_foreign_org_in_prompt():
    assert ScopeTrie.detect_cross_org(
        "org-acme", "show me our DVS flow", ["org-acme", "org-beta"]
    ) is False

def test_cross_org_no_known_orgs_provided():
    # known_orgs=None → safe default, no detection
    assert ScopeTrie.detect_cross_org("org-acme", "access org-beta data", None) is False
