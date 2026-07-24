"""Attack bank — known attacks as vectors, brute-force nearest-neighbour lookup.

The bank is two files that ship with the repo:
  * ``models/attack_bank.npz``  — float32 matrix, one L2-normalised row per attack
  * ``models/attack_bank.json`` — parallel metadata: [{id, text, rule_id, source}]

Lookup is a single matmul: ``matrix @ query`` gives the cosine similarity to every
row at once (both sides are normalised). At ~2,000 rows this is microseconds — no
FAISS, no vector database, nothing to operate. Adding a new attack is appending one
row and one metadata entry; no retraining, no redeploy of a model.

Built offline by ``tools/build_bank.py`` from the curated corpus + red-team prompts
+ mutations. Loaded once at process start via ``load_bank()``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from app.config import settings

if TYPE_CHECKING:
    import numpy as np

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BankEntry:
    """Metadata for one attack in the bank."""

    id: str
    text: str
    rule_id: str
    source: str  # "redteam" | "corpus" | "mutation"


class AttackBank:
    """An in-memory attack bank with cosine nearest-neighbour lookup."""

    def __init__(self, matrix: "np.ndarray", entries: list[BankEntry]) -> None:
        if matrix.shape[0] != len(entries):
            raise ValueError("bank matrix rows must match metadata length")
        self._matrix = matrix          # (N, D), each row L2-normalised
        self._entries = entries

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> list[BankEntry]:
        return self._entries

    def nearest(self, vec: "np.ndarray") -> Optional[tuple[float, BankEntry]]:
        """Return (cosine_similarity, entry) for the closest attack, or None if empty.

        ``vec`` must be L2-normalised (``embed`` returns normalised vectors), so the
        dot product is cosine similarity directly.
        """
        if len(self._entries) == 0:
            return None
        import numpy as np

        sims = self._matrix @ vec            # (N,) cosine similarities
        idx = int(np.argmax(sims))
        return float(sims[idx]), self._entries[idx]


def _bank_paths() -> tuple[Path, Path]:
    base = Path(settings.KNN_BANK_PATH)
    return base.with_suffix(".npz"), base.with_suffix(".json")


def load_bank() -> Optional[AttackBank]:
    """Load the attack bank from disk; None if the files are missing/unreadable.

    Never raises — a missing bank disables the similarity tier without taking the
    pipeline down, exactly like a missing model disables the classifier tier.
    """
    npz_path, json_path = _bank_paths()
    if not npz_path.exists() or not json_path.exists():
        logger.info("Attack bank not found at %s / %s; similarity tier disabled",
                    npz_path, json_path)
        return None
    try:
        import numpy as np

        matrix = np.load(npz_path)["vectors"].astype(np.float32)
        raw = json.loads(json_path.read_text(encoding="utf-8"))
        entries = [BankEntry(id=r["id"], text=r["text"], rule_id=r["rule_id"],
                             source=r.get("source", "corpus")) for r in raw]
        bank = AttackBank(matrix, entries)
        logger.info("Attack bank loaded: %d entries, dim %d", len(bank), matrix.shape[1])
        return bank
    except Exception as exc:  # corrupt file, shape mismatch, bad JSON
        logger.warning("Attack bank failed to load (%r); similarity tier disabled", exc)
        return None


def save_bank(matrix: "np.ndarray", entries: list[dict]) -> None:
    """Write the bank to disk (used offline by tools/build_bank.py)."""
    import numpy as np

    npz_path, json_path = _bank_paths()
    npz_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(npz_path, vectors=matrix.astype(np.float32))
    json_path.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Attack bank written: %d entries -> %s", len(entries), npz_path)
