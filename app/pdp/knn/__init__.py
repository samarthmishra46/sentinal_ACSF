"""Shared semantic layer for the PDP (V2).

``embed`` turns a prompt into a vector once per request (memoized); ``bank``
holds known attacks as vectors and answers "what known attack is this closest
to?". Two consumers share the single embedding:

  * the kNN cascade in ``app/pdp/detectors/injection_ml.py`` (similarity match)
  * the domain-intent classifier in ``app/pdp/detectors/intent_ml.py``

Everything degrades to a no-op if ``sentence-transformers`` is not installed, so
the base install and the deterministic red-team gate are unaffected.
"""

from app.pdp.knn.bank import AttackBank, BankEntry, load_bank
from app.pdp.knn.embed import embed, embedding_available, embedding_dim

__all__ = [
    "embed",
    "embedding_available",
    "embedding_dim",
    "AttackBank",
    "BankEntry",
    "load_bank",
]
