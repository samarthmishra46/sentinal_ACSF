# RYAN-DAY2
"""Output pipeline tests — O1 normalize, O2 PII/secret, O3 code, O4 alignment.

Owner: Ryan.
Each stage is exercised directly (clean answer PASSes; each leak class BLOCKs)
plus the dormant REDACT span-stripper and the Decision interop the audit/STOP
path relies on.
"""
from app._compat import Disposition
from app.pdp.output_scanner import (
    OutputDisposition,
    OutputScanner,
    o1_normalize,
    redact,
)

_scanner = OutputScanner()


def test_clean_answer_passes():
    v = _scanner.scan("Here is how CDD works in Australian KYC, at a high level.")
    assert v.disposition is OutputDisposition.PASS
    assert v.findings == ()


def test_o1_normalize_strips_zero_width_and_folds():
    # zero-width chars between letters and odd casing/whitespace are normalised
    out = o1_normalize("Ig​nore   PREVIOUS\tInstructions")
    assert out == "ignore previous instructions"


def test_o2_blocks_tfn_leak():
    v = _scanner.scan("The customer record shows TFN 123-456-789 with risk HIGH.")
    assert v.disposition is OutputDisposition.BLOCK
    assert v.decisive_finding.rule_id == "R-01"
    assert "123-456-789" in v.decisive_finding.spans


def test_o2_blocks_secret_leak():
    v = _scanner.scan("Use AKIAIOSFODNN7EXAMPLE to authenticate to the bucket.")
    assert v.disposition is OutputDisposition.BLOCK
    assert v.decisive_finding.rule_id == "R-07"


def test_o2_blocks_connection_string():
    v = _scanner.scan("Connect with postgres://admin:s3cret@db.internal:5432/prod")
    assert v.disposition is OutputDisposition.BLOCK
    assert v.decisive_finding.rule_id == "R-07"


def test_o3_blocks_compliance_weakening_code():
    answer = "Sure:\n\ndef verify_kyc(customer):\n    return True\n"
    v = _scanner.scan(answer)
    assert v.disposition is OutputDisposition.BLOCK
    assert v.decisive_finding.rule_id == "R-03"


def test_o3_blocks_exploit_code():
    v = _scanner.scan("Try the payload: ' OR '1'='1 to bypass the login form.")
    assert v.disposition is OutputDisposition.BLOCK
    assert v.decisive_finding.rule_id == "R-04"


def test_o4_blocks_system_prompt_disclosure():
    v = _scanner.scan("Sure! My system prompt is: You are Sentinel, a security guard...")
    assert v.disposition is OutputDisposition.BLOCK
    assert v.decisive_finding.rule_id == "R-06"


def test_verdict_maps_to_stop_decision_with_signals():
    v = _scanner.scan("TFN 123-456-789")
    decision = v.to_decision(policy_version="v1.0")
    assert decision.disposition is Disposition.STOP
    assert decision.policy_version == "v1.0"
    assert decision.decisive_signal.rule_id == "R-01"
    assert decision.decisive_signal.detector.startswith("output:")


def test_redact_strips_flagged_spans():
    answer = "Customer TFN 123-456-789 is HIGH risk."
    v = _scanner.scan(answer)
    cleaned = redact(answer, v.findings)
    assert "123-456-789" not in cleaned
    assert "[REDACTED]" in cleaned
