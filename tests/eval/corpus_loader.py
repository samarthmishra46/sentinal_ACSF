"""Loader for the curated evaluation corpus (Phase 0, V2).

The 13 red-team prompts in ``tests/redteam/prompts.yaml`` prove the detectors
handle those 13 exact strings; they are far too few to *measure* generalisation
or false positives honestly. This module loads a larger curated corpus of
domain-realistic malicious and benign prompts (``tests/eval/corpus/*.jsonl``),
weighted toward the compliance-intent categories (R-02/03/05/09) where V1's
surviving bypasses live and where a naive corpus is thinnest.

Format — one JSON object per line:

    malicious.jsonl:  {"id", "prompt", "rule", "category", "role", "tenant"}
    benign.jsonl:     {"id", "prompt", "category", "role", "tenant"}

``rule`` is absent on benign rows. ``role``/``tenant`` default to Engineer /
firm-alpha, matching ``tests/eval/harness._ctx``.

The corpus also seeds the Phase-2 attack bank (``tools/build_bank.py``), so it is
the single source of curated attack text for the whole V2 effort.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
MALICIOUS_FILE = CORPUS_DIR / "malicious.jsonl"
BENIGN_FILE = CORPUS_DIR / "benign.jsonl"


@dataclass(frozen=True)
class CorpusEntry:
    """One curated prompt with its ground-truth label."""

    id: str
    prompt: str
    category: str
    role: str
    tenant: str
    should_block: bool
    rule: str | None  # expected rule for malicious rows; None for benign


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _entry(row: dict, should_block: bool) -> CorpusEntry:
    return CorpusEntry(
        id=row["id"],
        prompt=" ".join(row["prompt"].split()),
        category=row.get("category", ""),
        role=row.get("role", "Engineer"),
        tenant=row.get("tenant", "firm-alpha"),
        should_block=should_block,
        rule=row.get("rule"),
    )


def load_malicious() -> list[CorpusEntry]:
    """Curated malicious prompts (expect STOP/ESCALATE)."""
    return [_entry(r, True) for r in _read_jsonl(MALICIOUS_FILE)]


def load_benign() -> list[CorpusEntry]:
    """Curated benign prompts, including near-misses (expect ALLOW)."""
    return [_entry(r, False) for r in _read_jsonl(BENIGN_FILE)]


def load_corpus() -> list[CorpusEntry]:
    """The full curated corpus, malicious first."""
    return load_malicious() + load_benign()
