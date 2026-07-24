"""Sentence embedding — one model, memoized, shared by every semantic detector.

Both the kNN similarity check and the intent classifier need the prompt as a
vector. Embedding is the expensive part (~5-10ms on CPU); the consumers are
cheap (a dot product). So we embed **once per prompt** and cache it, and both
detectors read the same vector. This is what keeps the intent classifier nearly
free on top of the similarity match.

Design mirrors ``app/pdp/detectors/injection_ml.py``:
  * lazy singleton load with a three-state sentinel (_UNSET / None / loaded);
  * any failure (missing lib, no network, bad model) → None, never raises;
  * off by default at the call sites via KNN_ENABLED — this module just provides
    the capability.

Model default: sentence-transformers/all-MiniLM-L6-v2 (~80MB, 384-dim). Small
enough for a laptop and the Render free tier, unlike the DeBERTa classifier.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import TYPE_CHECKING, Optional

from app.config import settings

if TYPE_CHECKING:  # numpy only needed for the type hint; import stays lazy at runtime
    import numpy as np

logger = logging.getLogger(__name__)

_UNSET = object()
_model: object = _UNSET


def _load_model():
    """Load the sentence-transformer once; None if unavailable. Never raises."""
    global _model
    if _model is not _UNSET:
        return _model
    try:
        from sentence_transformers import SentenceTransformer  # heavy; lazy

        _model = SentenceTransformer(settings.KNN_MODEL_NAME)
        logger.info("Embedding model loaded: %s", settings.KNN_MODEL_NAME)
    except Exception as exc:  # ImportError, download failure, incompatible version
        logger.warning(
            "Embedding model unavailable (%s): %r; semantic layer disabled",
            settings.KNN_MODEL_NAME, exc,
        )
        _model = None
    return _model


def embedding_available() -> bool:
    """True if the embedding model loaded — used by /health and detectors."""
    return _load_model() is not None


def embedding_dim() -> Optional[int]:
    """Vector dimension of the loaded model, or None if unavailable."""
    model = _load_model()
    if model is None:
        return None
    return int(model.get_sentence_embedding_dimension())


@lru_cache(maxsize=2048)
def _embed_cached(text: str) -> Optional["np.ndarray"]:
    """L2-normalised embedding of ``text``; None if the model is unavailable.

    Cached so two detectors evaluating the same prompt in one request share a
    single forward pass. Normalised so a dot product against the (also
    normalised) attack bank is exactly cosine similarity.
    """
    model = _load_model()
    if model is None:
        return None
    import numpy as np

    vec = model.encode([text], normalize_embeddings=True)[0]
    return np.asarray(vec, dtype=np.float32)


def embed(text: str) -> Optional["np.ndarray"]:
    """Return the memoized, L2-normalised embedding of ``text`` (or None).

    Whitespace is collapsed so trivially different spacing hits the same cache
    entry and the same vector.
    """
    return _embed_cached(" ".join(text.split()))
