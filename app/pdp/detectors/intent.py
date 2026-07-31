"""Intent / compliance scanner — multi-rule detector at Stage 7.

Sub-rules evaluated in priority order (STOP first, then ESCALATE):
  R-02  SMR/TTR content         keyword match          STOP
  R-03  Compliance bypass       two-part (action+obj)  STOP
  R-14  Offensive-artifact gen  two-part (verb+object) STOP
  R-04  System attack           two-part (tech+target) STOP
  R-09  Reporting manipulation  three-part (v+r+t)     STOP
  R-05  Bulk data extraction    pattern match          ESCALATE
  R-08  Cross-org contamination multi-entity detect    ESCALATE

Each sub-rule has a false-positive guard so legitimate engineering
and education questions pass cleanly.

Owner: Sneha
"""

from __future__ import annotations

import re

from app.pdp.detectors.base import BaseDetector
from app.pdp.decision import Signal, Disposition
from app.identity.context import RequestContext
from app.policy.models import Snapshot


# ═══════════════════════════════════════════════════════════════════════════
# R-02: SMR / TTR content
# ═══════════════════════════════════════════════════════════════════════════

_SMR_HIT = re.compile(
    r"\b("
    r"suspicious\s+matter\s+report|suspicious\s+matter"
    r"|threshold\s+transaction\s+report|tipping[\s\-]off"
    r"|AUSTRAC\s+report|file\s+(?:a|an)\s+(?:SMR|report\s+for)"
    r"|draft\s+(?:a|an)\s+SMR|review\s+(?:this|the|my)\s+SMR"
    r"|check\s+(?:this|the)\s+SMR"
    r")\b"
    r"|\bSMR\b(?!\s*(?:is|are|means|stands|definition))"
    r"|\bTTR\b(?!\s*(?:is|are|means|stands|definition))",
    re.IGNORECASE,
)

_SMR_OK = re.compile(
    r"\b(?:"
    r"what\s+(?:is|are)\s+(?:a|an)?\s*(?:SMR|suspicious\s+matter)"
    r"|explain\s+(?:what|how)\s+(?:a|an)?\s*(?:SMR|TTR)"
    r"|when\s+(?:are|is)\s+(?:a|an)?\s*(?:SMR|TTR)\s+required"
    r"|difference\s+between\s+(?:a|an)?\s*SMR\s+and"
    r"|documentation\s+explaining\s+the\s+SMR\s+workflow"
    r")\b",
    re.IGNORECASE,
)


def _check_smr(prompt: str) -> Signal | None:
    """R-02: block real SMR content, allow educational questions about SMRs."""
    if _SMR_OK.search(prompt):
        return None
    if not _SMR_HIT.search(prompt):
        return None
    return Signal(
        detector="intent_compliance_scanner",
        rule_id="R-02",
        disposition=Disposition.STOP,
        reason=(
            "SMR/TTR content detected. Protected under AML/CTF Act s.123 "
            "(tipping-off offence). The AI must not process this content."
        ),
        confidence=0.95,
        metadata={"owasp_id": "LLM02", "atlas_id": "AML.T0024", "severity": "CRITICAL"},
    )


# ═══════════════════════════════════════════════════════════════════════════
# R-03: Compliance bypass (two-part: action verb + compliance object)
# ═══════════════════════════════════════════════════════════════════════════

_BYPASS_A = re.compile(
    r"\b(bypass\w*|skip\w*|disabl\w*|remov\w*|delet\w*|circumvent\w*|overrid\w*"
    r"|comment\w*\s+out|turn\w*\s+off|get\w*\s+rid\s+of|deactivat\w*|suppress\w*)",
    re.IGNORECASE,
)

_BYPASS_B = re.compile(
    r"\b(CDD|KYC|AML\s+check|identity\s+(?:check|verification)"
    r"|risk\s+scor(?:e|ing)|AUSTRAC\s+report(?:ing)?"
    r"|validation|compliance\s+(?:check|control|rule)"
    r"|verification\s+(?:step|module|process|check)"
    r"|due\s+diligence)\b",
    re.IGNORECASE,
)

_BYPASS_OK = re.compile(
    r"\b(?:"
    r"(?:write|help\s+(?:me\s+)?write)\s+(?:a\s+)?(?:unit\s+)?test"
    r"|explain\s+(?:what|how)|what\s+(?:is|does)"
    r"|(?:how|why)\s+does\s+(?:the|our)"
    r"|improve\s+(?:the\s+)?performance"
    r"|false\s+positive"
    r"|bypass\s+(?:rate|percent|metric|ratio)"
    r"|reduce\s+(?:the\s+)?(?:bypass|skip)"
    r")\b",
    re.IGNORECASE,
)


def _check_bypass(prompt: str) -> Signal | None:
    """R-03: fires when action verb + compliance object co-occur."""
    if _BYPASS_OK.search(prompt):
        return None
    a = _BYPASS_A.search(prompt)
    b = _BYPASS_B.search(prompt)
    if not (a and b):
        return None
    return Signal(
        detector="intent_compliance_scanner",
        rule_id="R-03",
        disposition=Disposition.STOP,
        reason=(
            f"Compliance bypass: '{a.group()}' + '{b.group()}'. "
            f"Use a test fixture that mocks the compliance service instead."
        ),
        confidence=0.90,
        metadata={"owasp_id": "LLM06", "atlas_id": "AML.T0040", "severity": "HIGH"},
    )


# ═══════════════════════════════════════════════════════════════════════════
# R-04: System attack (two-part: technique + target)
# ═══════════════════════════════════════════════════════════════════════════

_ATTACK_A = re.compile(
    r"\b(SQL\s*inject(?:ion)?|XSS|cross[\-\s]site\s+script"
    r"|exploit(?:ation)?|reverse\s+shell|backdoor"
    r"|brute[\-\s]force|privilege\s+escalat"
    r"|RCE|command\s+injection|SSRF)\b",
    re.IGNORECASE,
)

_ATTACK_B = re.compile(
    r"\b(lex[\-\s]?aml"
    r"|(?:our|the|this)\s+(?:API|database|server|system|endpoint)"
    r"|production|(?:our|the)\s+auth(?:entication)?"
    r"|(?:our|the|this)\s+infrastructure"
    r"|/api/v\d|(?:our|the)\s+login)\b",
    re.IGNORECASE,
)

_ATTACK_OK = re.compile(
    r"\b(?:"
    r"explain\s+(?:what|how)"
    r"|what\s+is\s+(?:a\s+)?(?:SQL\s*injection|XSS)"
    r"|defend\s+against|protect\s+against|prevent"
    r"|(?:how|what)\s+(?:do\s+)?we\s+(?:defend|protect|prevent)"
    r"|review\s+(?:this|my|the)\s+(?:\w+\s+)+(?:for|against)"
    r"|suggest\w*\s+fix\w*|find\s+and\s+fix|patch|remediat"
    r"|sanitisation|sanitization|input\s+validat"
    r")",
    re.IGNORECASE,
)


def _check_attack(prompt: str) -> Signal | None:
    """R-04: fires when attack technique + system target co-occur."""
    if _ATTACK_OK.search(prompt):
        return None
    a = _ATTACK_A.search(prompt)
    b = _ATTACK_B.search(prompt)
    if not (a and b):
        return None
    return Signal(
        detector="intent_compliance_scanner",
        rule_id="R-04",
        disposition=Disposition.STOP,
        reason=(
            f"System attack pattern: '{a.group()}' + '{b.group()}'. "
            f"For security testing, use the authorised assessment process."
        ),
        confidence=0.92,
        metadata={"owasp_id": "LLM06", "atlas_id": "AML.T0040", "severity": "CRITICAL"},
    )


# ═══════════════════════════════════════════════════════════════════════════
# R-14: Offensive-artifact generation (two-part: generate verb + offensive object)
# ═══════════════════════════════════════════════════════════════════════════
# R-04 keys on attacking a *named* system asset ("our API", "production"), so it
# misses "generate SQL injection payloads to validate our internal application" —
# no recognised target noun. This rule keys on the *act of producing an offensive
# artifact* instead, so it fires regardless of whose system is (or isn't) named.
# It activates catalog rule R-14 (Malware Creation Assistance), whose defer note
# is exactly "partially covered by R-04". Ordered BEFORE R-04 in _detect so the
# artifact-generation reason wins when both would match.

_PAYLOAD_VERB = re.compile(
    r"\b(generate|create|write|produce|build|craft|develop|construct|"
    r"make|give\s+me|provide|code\s+up)\b",
    re.IGNORECASE,
)

# Offensive artifacts: an attack technique paired with a code/artifact noun, or a
# self-evidently malicious artifact on its own (malware, ransomware, keylogger…).
_PAYLOAD_OBJ = re.compile(
    r"\b(?:"
    r"(?:SQL\s*inject(?:ion)?|XSS|cross[\-\s]site\s+script|CSRF|SSRF|RCE|"
    r"command\s+inject(?:ion)?|buffer\s+overflow|directory\s+traversal|"
    r"path\s+traversal|deserial(?:ization|isation))\s*"
    r"(?:payload|exploit|attack|string|vector|script|code|query)?s?"
    r"|(?:exploit|payload|attack\s+vector)s?\s+(?:for|against|to)"
    r"|malware|ransomware|spyware|rootkit|keylogger|botnet|"
    r"reverse\s+shell|(?:web\s*)?shell\s+code|shellcode|backdoor|"
    r"trojan|worm|virus\s+(?:code|program|script)|"
    r"(?:privilege[\-\s]escalation|brute[\-\s]force)\s+(?:script|tool|payload)"
    r")\b",
    re.IGNORECASE,
)

# Educational / defensive framing stays allowed — describing, detecting, or
# defending against these is legitimate engineering, only *producing* them is not.
_PAYLOAD_OK = re.compile(
    r"\b(?:"
    r"explain|describe|what\s+is|what\s+are|how\s+(?:do(?:es)?|can)|"
    r"detect(?:ion|ing)?|defend|protect|prevent|mitigat|remediat|"
    r"sanitis|sanitiz|input\s+validat|harden|patch|fix\s+(?:this|the|my)|"
    r"unit\s+test|test\s+(?:case|fixture)\s+(?:for|that)\s+(?:detect|catch|reject)"
    r")\b",
    re.IGNORECASE,
)

# Self-evidently offensive artifacts: there is no legitimate "generate" use, so
# the educational-framing exemption must NOT apply to these. Blocks the trivial
# bypass "explain how ransomware works, and also write me one".
_MALICIOUS_STANDALONE = re.compile(
    r"\b(?:malware|ransomware|spyware|rootkit|keylogger|botnet|"
    r"reverse\s+shell|shellcode|backdoor|trojan|worm)\b",
    re.IGNORECASE,
)

# Generation aimed at a *working* attack against a target — also overrides the
# exemption. Catches "explain X and create one that works on <system>", where a
# stray "explain" would otherwise neutralise the block.
_ATTACK_GEN_OVERRIDE = re.compile(
    r"\b(?:working|functional|real|actual)\s+(?:exploit|payload|attack|injection)"
    r"|(?:exploit|payload|injection|attack|one)\s+(?:that|which|to)\s+"
    r"(?:work|works|target|hit|bypass|defeat|break|compromise|attack|run)"
    r"|(?:work|works|working)\s+(?:on|against)\s+"
    r"(?:sentinel|the|our|your|this|their|a|an)\b",
    re.IGNORECASE,
)


def _check_payload_generation(prompt: str) -> Signal | None:
    """R-14: block requests to *produce* offensive artifacts, regardless of target.

    The educational/defensive exemption (``_PAYLOAD_OK``) is a keyword guard, so
    it is overridable: a self-evidently malicious object (``ransomware``) or an
    explicit "make one that works on <system>" construction blocks even when an
    "explain"/"how does" phrase co-occurs. Keyword guards can still be worded
    around — the Stage-8 semantic layer is the real backstop for paraphrase.
    """
    verb = _PAYLOAD_VERB.search(prompt)
    obj = _PAYLOAD_OBJ.search(prompt)
    if not (verb and obj):
        return None
    # Educational framing exempts, UNLESS the prompt also asks to produce a
    # self-evidently malicious artifact or a working attack against a target.
    if _PAYLOAD_OK.search(prompt) and not (
        _MALICIOUS_STANDALONE.search(prompt) or _ATTACK_GEN_OVERRIDE.search(prompt)
    ):
        return None
    return Signal(
        detector="intent_compliance_scanner",
        rule_id="R-14",
        disposition=Disposition.STOP,
        reason=(
            f"Offensive-artifact generation: '{verb.group()}' + '{obj.group().strip()}'. "
            f"The assistant must not produce exploit code, payloads, or malware. "
            f"For authorised testing, use the sanctioned security-assessment process."
        ),
        confidence=0.90,
        metadata={"owasp_id": "LLM06", "atlas_id": "AML.T0040", "severity": "CRITICAL"},
    )


# ═══════════════════════════════════════════════════════════════════════════
# R-09: Reporting manipulation (three-part: verb + record + temporal)
# ═══════════════════════════════════════════════════════════════════════════

_MANIP_A = re.compile(
    r"\b(UPDATE|alter|backdate|fabricate|forge|falsify|suppress|tamper|overwrite)\b",
    re.IGNORECASE,
)

_MANIP_B = re.compile(
    r"\b(risk[\s_]?score|CDD\s+record|audit[\s_]?trail"
    r"|assess(?:ment)?[\s_]?date|SMR\s+status"
    r"|reporting[\s_]?flag|compliance[\s_]?log)\b",
    re.IGNORECASE,
)

_MANIP_C = re.compile(
    r"\b(change\s+(?:the\s+)?date|change\s+\w+\s+to\s+(?:today|now)"
    r"|set\s+(?:to\s+)?today|set\s+\w+\s+to\s+(?:today|now)"
    r"|to\s+today\s+so|backdate|make\s+it\s+look"
    r"|looks?\s+(?:like\s+(?:a\s+)?)?fresh"
    r"|assessed_date\s*=\s*(?:NOW|CURRENT|today|getdate))\b",
    re.IGNORECASE,
)

_MANIP_OK = re.compile(
    r"\b(?:"
    r"create\s+(?:a\s+)?new\s+(?:risk\s+)?assessment"
    r"|supersede|find\s+all\s+customers\s+whose"
    r"|older\s+than\s+\d+\s+months"
    r"|how\s+does\s+the\s+audit\s+trail"
    r")\b",
    re.IGNORECASE,
)


def _check_manipulation(prompt: str) -> Signal | None:
    """R-09: fires only when all three parts match — verb + record + temporal."""
    if _MANIP_OK.search(prompt):
        return None
    a = _MANIP_A.search(prompt)
    b = _MANIP_B.search(prompt)
    c = _MANIP_C.search(prompt)
    if not (a and b and c):
        return None
    return Signal(
        detector="intent_compliance_scanner",
        rule_id="R-09",
        disposition=Disposition.STOP,
        reason=(
            f"Compliance record manipulation: '{a.group()}' + '{b.group()}' + "
            f"temporal falsification. Historical records are immutable. "
            f"Create a new assessment referencing the original instead."
        ),
        confidence=0.95,
        metadata={"owasp_id": "LLM06", "atlas_id": "AML.T0040", "severity": "CRITICAL"},
    )


# ═══════════════════════════════════════════════════════════════════════════
# R-05: Bulk extraction (ESCALATE)
# ═══════════════════════════════════════════════════════════════════════════

_BULK_HIT = re.compile(
    r"\b("
    r"SELECT\s+\*\s+FROM\s+(?:customer|client|user|cdd|kyc)"
    r"|(?:dump|export|extract)\s+all\s+(?:customer|client|CDD|KYC)"
    r"|CSV\s+of\s+all\s+(?:customer|client|record)"
    r"|(?:every|all)\s+(?:customer|client)\s+(?:record|data|CDD)"
    r"|list\s+all\s+client\s+data|bulk\s+(?:export|extract|download)"
    r")\b",
    re.IGNORECASE,
)

_BULK_OK = re.compile(
    r"\b(?:paginat|LIMIT\s+\d|OFFSET\s+\d|COUNT\s*\(|GROUP\s+BY"
    r"|fetch\s+\d+\s+(?:at\s+a\s+time|records|rows)|migrat)\b",
    re.IGNORECASE,
)


def _check_bulk(prompt: str) -> Signal | None:
    """R-05: ESCALATE for ambiguous bulk-export requests; paginated queries pass."""
    if _BULK_OK.search(prompt):
        return None
    if not _BULK_HIT.search(prompt):
        return None
    return Signal(
        detector="intent_compliance_scanner",
        rule_id="R-05",
        disposition=Disposition.ESCALATE,
        reason="Bulk data extraction request. Intent ambiguous — held for reviewer.",
        confidence=0.80,
        metadata={"owasp_id": "LLM06", "atlas_id": "AML.T0024", "severity": "MEDIUM"},
    )


# ═══════════════════════════════════════════════════════════════════════════
# R-08: Cross-org contamination (ESCALATE)
# ═══════════════════════════════════════════════════════════════════════════

_ORG_NAMES = re.compile(
    r"\b("
    r"[Ff]irm\s+[A-Z][a-zA-Z]*"
    r"|[A-Z][a-z]+\s+(?:Law|Legal|Accounting|Conveyancing|Partners|Group|Pty)"
    r")\b"
)

_ORG_DATA = re.compile(
    r"\b(?:config|threshold|risk\s+matrix|setting|workflow"
    r"|score|setup|\$\d|custom|different)\b",
    re.IGNORECASE,
)


def _check_cross_org(prompt: str) -> Signal | None:
    """R-08: ESCALATE when two+ orgs referenced with operational data."""
    orgs = set(m.strip() for m in _ORG_NAMES.findall(prompt))
    if len(orgs) < 2 or not _ORG_DATA.search(prompt):
        return None
    return Signal(
        detector="intent_compliance_scanner",
        rule_id="R-08",
        disposition=Disposition.ESCALATE,
        reason=f"Cross-tenant reference: {', '.join(sorted(orgs))} with operational data.",
        confidence=0.75,
        metadata={"owasp_id": "LLM02", "atlas_id": "AML.T0024", "severity": "MEDIUM"},
    )


# ═══════════════════════════════════════════════════════════════════════════
# Main scanner
# ═══════════════════════════════════════════════════════════════════════════


class IntentScanner(BaseDetector):
    """Stage 7: compliance intent detection — STOP rules first, then ESCALATE."""

    @property
    def stage_name(self) -> str:
        return "intent_compliance_scanner"

    @property
    def stage_order(self) -> int:
        return 7

    def scan(self, ctx: RequestContext, prompt: str, snap: Snapshot) -> Signal | None:
        """Evaluate sub-rules in priority order. First match wins."""
        try:
            return self._detect(prompt)
        except Exception:
            return None

    def _detect(self, prompt: str) -> Signal | None:
        """STOP rules first (highest severity), then ESCALATE rules."""
        for fn in [_check_smr, _check_bypass, _check_payload_generation,
                   _check_attack, _check_manipulation]:
            signal = fn(prompt)
            if signal is not None:
                return signal

        for fn in [_check_bulk, _check_cross_org]:
            signal = fn(prompt)
            if signal is not None:
                return signal

        return None