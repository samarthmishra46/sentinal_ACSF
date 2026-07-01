// ─────────────────────────────────────────────────────────────────────
// Sentinel Cedar Authorization Policies — v1
// File: policies/v1/authz.cedar
// Owner: Sneha (Cedar policy files), Anamika (Cedar engine)
//
// These rules run at pipeline stages 2–3, BEFORE the content
// detectors. They answer: "is this role allowed this action?"
//
// If Cedar FORBIDS → request blocked, detectors never run.
// If Cedar PERMITS → request continues to Stage 4+ detectors.
//
// V1 roles:
//   Engineer          — code, debug, architecture, documentation
//   ComplianceOfficer — compliance docs, policy, AML/CTF guidance
//   SecurityReviewer  — escalation review, security analysis
//   Support           — basic queries only
//
// V1 dispositions: ALLOW, ESCALATE, STOP only.
// REDACT and CONSTRAIN deferred to V2.
// ─────────────────────────────────────────────────────────────────────


// ═══════ R1: ENGINEER CAPABILITIES (4 permits) ═══════

// Engineers get code help, architecture, debugging, and documentation.
permit (
    principal is User,
    action == Action::"use_assistant",
    resource == Resource::"code_help"
)
when { principal.role == "Engineer" };

permit (
    principal is User,
    action == Action::"use_assistant",
    resource == Resource::"architecture"
)
when { principal.role == "Engineer" };

permit (
    principal is User,
    action == Action::"use_assistant",
    resource == Resource::"debugging"
)
when { principal.role == "Engineer" };

permit (
    principal is User,
    action == Action::"use_assistant",
    resource == Resource::"documentation"
)
when { principal.role == "Engineer" || principal.role == "ComplianceOfficer" };


// ═══════ R2: COMPLIANCE OFFICER CAPABILITIES (2 permits) ═══════

// Compliance officers get compliance guidance and policy drafting.
permit (
    principal is User,
    action == Action::"use_assistant",
    resource == Resource::"compliance_guidance"
)
when { principal.role == "ComplianceOfficer" };

permit (
    principal is User,
    action == Action::"use_assistant",
    resource == Resource::"policy_drafting"
)
when { principal.role == "ComplianceOfficer" };


// ═══════ R3: SECURITY REVIEWER CAPABILITIES (2 permits) ═══════

// Security reviewers handle escalated requests and security analysis.
permit (
    principal is User,
    action == Action::"review_escalation",
    resource == Resource::"escalation_queue"
)
when { principal.role == "SecurityReviewer" };

permit (
    principal is User,
    action == Action::"use_assistant",
    resource == Resource::"security_analysis"
)
when { principal.role == "SecurityReviewer" };


// ═══════ R3b: SUPPORT STAFF (1 permit, restricted) ═══════

// Support gets basic queries only — no sensitive capabilities.
permit (
    principal is User,
    action == Action::"use_assistant",
    resource == Resource::"basic_query"
)
when { principal.role == "Support" };


// ═══════ R4: UNIVERSAL FORBIDS (5 rules) ═══════

// Nobody — regardless of role — can do these three things.

// 4a: No direct customer data access through the AI
forbid (
    principal is User,
    action == Action::"access_customer_data",
    resource
);

// 4b: No modification of compliance records through the AI
forbid (
    principal is User,
    action == Action::"modify_compliance_record",
    resource
);

// 4c: No compliance decisions by the AI (P-07: your team decides)
forbid (
    principal is User,
    action == Action::"make_compliance_decision",
    resource
);

// 4d: Support cannot access security analysis
forbid (
    principal is User,
    action == Action::"use_assistant",
    resource == Resource::"security_analysis"
)
when { principal.role == "Support" };

// 4e: Support cannot access compliance guidance
forbid (
    principal is User,
    action == Action::"use_assistant",
    resource == Resource::"compliance_guidance"
)
when { principal.role == "Support" };


// ═══════ R5: TENANT BOUNDARY ENFORCEMENT (1 rule) ═══════

// All access must be within the user's assigned tenant.
// If the resource belongs to a different tenant, block it.
// Exception: SecurityReviewers can cross boundaries for
// investigations — but this is logged at elevated severity.
forbid (
    principal is User,
    action == Action::"use_assistant",
    resource
)
when { resource.tenant != principal.tenant }
unless { principal.role == "SecurityReviewer" };