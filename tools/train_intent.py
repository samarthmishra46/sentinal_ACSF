"""Train the domain-intent classifier and export it as plain JSON (Phase 4).

A multi-class logistic regression over the shared MiniLM embedding. Labels:
{benign, R-02, R-03, R-05, R-09}. Trained offline on the Phase-3 synthetic data;
the runtime detector (app/pdp/detectors/intent_ml.py) needs neither sklearn nor
torch — just numpy over the exported coefficients, reusing the embedding the kNN
tier already computed.

Exports JSON coefficients (not pickle): pickle is a code-execution surface, is
tied to a sklearn version, and is unreviewable in a diff. JSON is none of those.

Refuses to run without data/synthetic/splits/REVIEWED.ok — synthetic labels are
weak until a human signs off (tools/prepare_dataset.py writes the review sample).

    PYTHONPATH=. python tools/train_intent.py
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from app.config import settings
from app.pdp.knn.embed import embed, embedding_available

SPLIT_DIR = Path("data/synthetic/splits")
SIGNOFF = SPLIT_DIR / "REVIEWED.ok"
OUT = Path(settings.INTENT_MODEL_PATH) if hasattr(settings, "INTENT_MODEL_PATH") \
    else Path("models/intent_clf.json")


def _load(path: Path) -> tuple[list[str], list[str]]:
    texts, labels = [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            r = json.loads(line)
            texts.append(r["text"])
            labels.append(r["label"])
    return texts, labels


def _embed_matrix(texts: list[str]) -> np.ndarray:
    return np.vstack([embed(t) for t in texts]).astype(np.float32)


def main() -> int:
    if not SIGNOFF.exists():
        print(f"ERROR: review sign-off missing ({SIGNOFF}).")
        print("Run tools/prepare_dataset.py, read the review sample, then create it.")
        return 1
    if not embedding_available():
        print('ERROR: embedding model unavailable. Install: pip install -e ".[ml]"')
        return 1
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import classification_report, confusion_matrix

    train_texts, train_labels = _load(SPLIT_DIR / "train.jsonl")
    test_texts, test_labels = _load(SPLIT_DIR / "test.jsonl")
    print(f"train={len(train_texts)}  test={len(test_texts)}  embedding...")

    Xtr, Xte = _embed_matrix(train_texts), _embed_matrix(test_texts)

    clf = LogisticRegression(max_iter=2000, C=2.0, class_weight="balanced")
    clf.fit(Xtr, train_labels)

    pred = clf.predict(Xte)
    print("\nHeld-out report (split by parent — no paraphrase leakage):")
    print(classification_report(test_labels, pred, digits=3, zero_division=0))
    print("labels:", list(clf.classes_))
    print("confusion:\n", confusion_matrix(test_labels, pred, labels=list(clf.classes_)))

    # Export plain JSON: weights (n_classes x n_features), intercepts, label order.
    payload = {
        "labels": list(clf.classes_),
        "weights": clf.coef_.astype(np.float32).tolist(),
        "intercepts": clf.intercept_.astype(np.float32).tolist(),
        "embedding_model": settings.KNN_MODEL_NAME,
        "n_features": int(Xtr.shape[1]),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "train_size": len(train_texts),
        "dataset_sha256": hashlib.sha256(
            (SPLIT_DIR / "train.jsonl").read_bytes()).hexdigest()[:16],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload), encoding="utf-8")
    size_kb = OUT.stat().st_size / 1024
    print(f"\nexported -> {OUT}  ({size_kb:.1f} KB, no pickle)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
