"""Prepare + validate the synthetic intent dataset for training (Phase 3).

Reads data/synthetic/*.jsonl, then:
  * dedups exact texts across every file;
  * splits train/test **by parent_id** — every mutation of a seed prompt goes to
    the SAME side. Random splitting would leak a prompt's own paraphrase into test
    and report a fake accuracy. This is the single most important discipline here;
  * reports label balance and per-strategy counts;
  * asserts no text appears in both splits and that benign near-misses survive;
  * writes a human-review sample and the splits to data/synthetic/splits/.

Training (tools/train_intent.py) refuses to run without the review sign-off file
this tool tells you to create — synthetic labels are weak until a human looks.

    PYTHONPATH=. python tools/prepare_dataset.py [--test-frac 0.25] [--seed 0]
"""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path

DATA_DIR = Path("data/synthetic")
SPLIT_DIR = DATA_DIR / "splits"
REVIEW_FILE = SPLIT_DIR / "review_sample.txt"
SIGNOFF_FILE = SPLIT_DIR / "REVIEWED.ok"


def _load_all() -> list[dict]:
    rows, seen = [], set()
    for path in sorted(DATA_DIR.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            key = r["text"].lower()
            if key not in seen:               # exact dedup across files
                seen.add(key)
                rows.append(r)
    return rows


def _split_by_parent(rows: list[dict], test_frac: float, seed: int):
    """All rows sharing a parent_id go to the same split — no paraphrase leakage."""
    parents = sorted({r["parent_id"] for r in rows})
    rng = random.Random(seed)
    rng.shuffle(parents)
    n_test = int(len(parents) * test_frac)
    test_parents = set(parents[:n_test])
    train = [r for r in rows if r["parent_id"] not in test_parents]
    test = [r for r in rows if r["parent_id"] in test_parents]
    return train, test


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                    encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-frac", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    rows = _load_all()
    SPLIT_DIR.mkdir(parents=True, exist_ok=True)
    train, test = _split_by_parent(rows, args.test_frac, args.seed)

    # Hard checks — fail loudly rather than train on a leaky/degenerate split.
    train_texts = {r["text"].lower() for r in train}
    test_texts = {r["text"].lower() for r in test}
    overlap = train_texts & test_texts
    assert not overlap, f"LEAK: {len(overlap)} texts in both splits"

    labels = Counter(r["label"] for r in rows)
    assert labels.get("benign", 0) >= 0.2 * len(rows), (
        f"benign near-misses collapsed: {labels.get('benign', 0)}/{len(rows)} "
        "— classifier will over-block")

    _write_jsonl(SPLIT_DIR / "train.jsonl", train)
    _write_jsonl(SPLIT_DIR / "test.jsonl", test)

    # Report.
    print(f"total unique rows: {len(rows)}   train: {len(train)}   test: {len(test)}")
    print("label balance:")
    for lbl, n in labels.most_common():
        print(f"  {lbl:8} {n:5}  ({n / len(rows):.0%})")
    strat = Counter(r["strategy"] for r in rows)
    print("by strategy:", dict(strat.most_common()))

    # Human-review sample: a few originals per label. Synthetic labels are weak
    # until someone reads them.
    rng = random.Random(args.seed)
    lines = ["REVIEW: confirm each line's label is correct, then create REVIEWED.ok",
             "=" * 70]
    by_label: dict[str, list[dict]] = {}
    for r in rows:
        if r["strategy"] == "original":
            by_label.setdefault(r["label"], []).append(r)
    for lbl, items in sorted(by_label.items()):
        lines.append(f"\n[{lbl}]")
        for r in rng.sample(items, min(8, len(items))):
            lines.append(f"  {r['text']}")
    REVIEW_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok = SIGNOFF_FILE.exists()
    print(f"\nreview sample -> {REVIEW_FILE}")
    print(f"sign-off {'PRESENT' if ok else 'MISSING'}: "
          f"{'training may proceed' if ok else f'read the sample, then: touch {SIGNOFF_FILE}'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
