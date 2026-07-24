"""Guards the Phase-0 evaluation corpus and the mutation label-flip fix."""

from __future__ import annotations

from tests.eval.corpus_loader import load_benign, load_corpus, load_malicious
from tests.eval.mutations import generate


def test_corpus_loads_and_is_labelled() -> None:
    mal, ben = load_malicious(), load_benign()
    assert len(mal) >= 40 and len(ben) >= 35
    assert all(e.should_block and e.rule for e in mal)
    assert all(not e.should_block and e.rule is None for e in ben)
    # ids unique across the whole corpus
    ids = [e.id for e in load_corpus()]
    assert len(ids) == len(set(ids))


def test_compliance_intent_is_represented() -> None:
    # The gap category must be present and weighted, or the eval can't measure it.
    rules = {e.rule for e in load_malicious()}
    assert {"R-02", "R-03", "R-05", "R-09"} <= rules


def test_base64_is_label_flipping_and_excluded_for_benign() -> None:
    # base64 injects an instruction -> must not be produced when preserving labels.
    strategies = {m.strategy for m in generate("Explain what an SMR is.", seed=0)}
    assert "base64" in strategies
    preserving = {m.strategy for m in generate(
        "Explain what an SMR is.", seed=0, label_preserving_only=True)}
    assert "base64" not in preserving
