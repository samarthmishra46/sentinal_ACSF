// ============================================================
// Sentinel V1 — Authorization Policies
// OWNER: Sneha (Day 2)
// USED BY: Anamika — app/pdp/authz/cedar_engine.py (_cedar_sdk_evaluate)
// ============================================================
//
// Sneha: fill in the real Cedar rules below for R1-R5.
// The Python-equivalent rules already exist in cedar_engine.py as a fallback.
// Once this file is complete, uncomment _cedar_sdk_evaluate() in cedar_engine.py.
//
// Cedar syntax reference:
//   permit(principal, action, resource) when { conditions };
//   forbid(principal, action, resource) unless { conditions };
//
// Entity types used: User, Action, Resource
// User attributes: role (String), tenant (String)
//
// ============================================================

// R-1: Engineers can chat and request code review
permit(
    principal in Role::"Engineer",
    action in [Action::"chat", Action::"code_review", Action::"arch_view", Action::"doc_access"],
    resource == Resource::"assistant"
);

// R-2: Support can only access documentation
permit(
    principal in Role::"Support",
    action == Action::"doc_access",
    resource == Resource::"assistant"
);

// R-3: SecurityReviewer can do everything an Engineer can + security review
permit(
    principal in Role::"SecurityReviewer",
    action in [Action::"chat", Action::"code_review", Action::"arch_view",
               Action::"doc_access", Action::"security_review"],
    resource == Resource::"assistant"
);

// R-4: ComplianceOfficer can access docs and trigger compliance review
permit(
    principal in Role::"ComplianceOfficer",
    action in [Action::"doc_access", Action::"compliance_review"],
    resource == Resource::"assistant"
);

// R-5: Deny everything not explicitly permitted (Cedar is deny-by-default)
// No additional forbid rule needed — Cedar's default is forbid unless permitted.

// ============================================================
// Sneha: add R-6 through R-9 rules here as needed for your detectors.
// Anamika will wire them in on Day 3.
// ============================================================
