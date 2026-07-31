"""Rebuild models/attack_bank.npz from models/attack_bank.json.

The attack bank is two files: the .json holds each attack's text + rule_id (text,
version-controllable), and the .npz holds the pre-computed embedding vectors
(binary). Hugging Face rejects committed binaries, so the .npz is NOT in git — it
is regenerated here, from the committed .json, at Docker build time (the embedding
model is already baked into the image).

Deterministic: embedding the same texts with the same model reproduces the same
vectors bit-for-bit, so the rebuilt bank is identical to the one built offline.

    PYTHONPATH=. python tools/rebuild_bank_vectors.py
"""

from __future__ import annotations

import json
from pathlib import Path

from app.config import settings
from app.pdp.knn.embed import embed, embedding_available


def main() -> int:
    if not embedding_available():
        print('ERROR: embedding model unavailable. Install: pip install -e ".[ml]"')
        return 1
    import numpy as np

    base = Path(settings.KNN_BANK_PATH)
    json_path, npz_path = base.with_suffix(".json"), base.with_suffix(".npz")
    if not json_path.exists():
        print(f"ERROR: {json_path} not found — nothing to rebuild from.")
        return 1

    rows = json.loads(json_path.read_text(encoding="utf-8"))
    print(f"embedding {len(rows)} attack texts from {json_path.name} ...")
    vectors = np.vstack([embed(r["text"]) for r in rows]).astype(np.float32)
    np.savez_compressed(npz_path, vectors=vectors)
    print(f"wrote {npz_path}  ({vectors.shape[0]} x {vectors.shape[1]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
