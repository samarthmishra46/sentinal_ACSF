"""Build the kNN attack bank from red-team prompts + curated corpus + mutations.

Offline, run on a laptop, not in the request path. Produces:
  models/attack_bank.npz   — float32 matrix, one L2-normalised row per attack
  models/attack_bank.json  — parallel [{id, text, rule_id, source}]

Sources (malicious only — the bank holds attacks, benign prompts stay out):
  * tests/redteam/prompts.yaml  — the 9 malicious red-team originals
  * tests/eval/corpus/malicious.jsonl — the curated domain attacks
  * label-preserving mutations of both (homoglyph / synonym / etc.) so the bank
    covers paraphrases, which is the whole point of a semantic match.

Usage:
    PYTHONPATH=. python tools/build_bank.py [--per-strategy N] [--seed S]

Re-run whenever the corpus grows or a new confirmed attack arrives from the
escalation queue. That append-and-rebuild loop is why a new attack is protected
the same day, with no model retraining.
"""

from __future__ import annotations

import argparse

from app.pdp.knn.bank import save_bank
from app.pdp.knn.embed import embed, embedding_available
from tests.eval.corpus_loader import load_malicious
from tests.eval.harness import _load_prompts
from tests.eval.mutations import generate


def _collect(per_strategy: int, seed: int) -> list[dict]:
    """Gather (id, text, rule_id, source) rows for every attack + its mutations."""
    rows: list[dict] = []
    seen_text: set[str] = set()

    def add(id_: str, text: str, rule_id: str, source: str) -> None:
        norm = " ".join(text.split())
        if norm and norm not in seen_text:
            seen_text.add(norm)
            rows.append({"id": id_, "text": norm, "rule_id": rule_id, "source": source})

    # Red-team malicious originals.
    for e in _load_prompts():
        if e.get("expected_decision", "ALLOW") != "ALLOW":
            rule = e.get("expected_rule", "R-06")
            add(e["id"], e["prompt"], rule, "redteam")
            for m in generate(e["prompt"], per_strategy=per_strategy, seed=seed):
                add(f"{e['id']}:{m.strategy}", m.text, rule, "mutation")

    # Curated corpus malicious originals.
    for c in load_malicious():
        rule = c.rule or "R-06"
        add(c.id, c.prompt, rule, "corpus")
        for m in generate(c.prompt, per_strategy=per_strategy, seed=seed):
            add(f"{c.id}:{m.strategy}", m.text, rule, "mutation")

    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the kNN attack bank.")
    ap.add_argument("--per-strategy", type=int, default=3)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    if not embedding_available():
        print("ERROR: embedding model unavailable. Install the `ml` extra:")
        print('  pip install -e ".[ml]"')
        return 1

    import numpy as np

    rows = _collect(args.per_strategy, args.seed)
    print(f"collected {len(rows)} unique attack strings; embedding...")
    vectors = np.vstack([embed(r["text"]) for r in rows]).astype(np.float32)
    save_bank(vectors, rows)
    print(f"bank written: {vectors.shape[0]} rows x {vectors.shape[1]} dims")

    # Quick sanity: distribution of sources.
    by_source: dict[str, int] = {}
    for r in rows:
        by_source[r["source"]] = by_source.get(r["source"], 0) + 1
    print("by source:", by_source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
