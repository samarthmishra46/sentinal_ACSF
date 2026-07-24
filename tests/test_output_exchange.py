"""Tests for O5 — the context-aware exchange check (answer scored vs prompt)."""

from __future__ import annotations

from app.pdp.output_scanner import OutputDisposition, OutputScanner, o5_exchange


def test_over_disclosure_blocked():
    # Prompt asks about one customer; answer volunteers many others → over-disclosure.
    prompt = "what is the risk status for customer-1001?"
    answer = ("Here are the records: customer-2001, customer-2002, customer-2003, "
              "customer-2004, customer-2005, customer-2006, customer-2007.")
    findings = o5_exchange(prompt, answer)
    assert findings and findings[0].disposition is OutputDisposition.BLOCK
    assert findings[0].rule_id == "R-05"


def test_answer_within_scope_passes():
    # Answer only discusses the customer the prompt referenced → no over-disclosure.
    prompt = "what is the risk status for customer-1001?"
    answer = "customer-1001 is currently rated LOW risk after the latest review."
    assert o5_exchange(prompt, answer) == []


def test_no_prompt_context_is_noop():
    assert o5_exchange("", "customer-2001 customer-2002 customer-2003 "
                           "customer-2004 customer-2005 customer-2006") == []


def test_scanner_wires_o5_into_verdict():
    prompt = "look up customer-1001"
    answer = " ".join(f"customer-{3000+i}" for i in range(8))
    verdict = OutputScanner().scan(answer, prompt=prompt)
    assert verdict.disposition is OutputDisposition.BLOCK
    assert any(f.scanner == "o5_exchange" for f in verdict.findings)
