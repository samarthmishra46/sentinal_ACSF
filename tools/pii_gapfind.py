"""PII coverage gap-finder (Phase 6) — offline, dependency-light.

We shipped regex-only PII (Presidio silently unavailable) and only found Indian
PAN was missing by manual accident. This tool answers "what else are we missing?"
systematically, WITHOUT putting a heavy model on the hot path:

  * runs the current PIIDetector over a curated set of international PII samples
    and reports which entity types it MISSES;
  * optionally, if `gliner` is installed, runs zero-shot NER over the eval corpus
    to surface entity types we never thought to write a regex for.

Runtime stays regex-only and fast; this is a laptop tool you re-run when the
corpus grows. The fix for a miss is: add a tested regex to app/pdp/detectors/pii.py.

    PYTHONPATH=. python tools/pii_gapfind.py
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.identity.context import RequestContext
from app.pdp.detectors.pii import PIIDetector
from app.policy.models import Snapshot

# Curated international PII samples (synthetic values). Each should be caught by
# *some* pattern once coverage is complete. Names/DOBs handled separately.
_SAMPLES: dict[str, list[str]] = {
    "AU TFN":            ["my TFN is 123-456-789"],
    "AU Passport":       ["passport N1234567"],
    "AU Medicare":       ["Medicare 2345 67890 1"],
    "Indian PAN":        ["PAN ABCDE1234F"],
    "Indian Aadhaar":    ["Aadhaar 2345 6789 0123", "aadhaar number 234567890123"],
    "IBAN":              ["IBAN GB33BUKB20201555555555", "DE89370400440532013000"],
    "SWIFT/BIC":         ["SWIFT code DEUTDEFF", "BIC NWBKGB2L"],
    "US SSN":            ["SSN 123-45-6789"],
    "Credit card":       ["card 4111 1111 1111 1111", "4111111111111111"],
    "Email":             ["contact jane.doe@example.com"],
    "IPv4":              ["from 192.168.10.24"],
}


def _ctx() -> RequestContext:
    return RequestContext(user_id="gapfind", role="Engineer", tenant="firm-alpha",
                          owned_services=["svc"], session_token="t")


def main() -> int:
    det = PIIDetector()
    snap = Snapshot(version="gapfind", created_at=datetime.now(timezone.utc))
    ctx = _ctx()

    print("PII coverage — current regex detector vs curated international samples")
    print("=" * 68)
    caught, missed = [], []
    for entity, samples in _SAMPLES.items():
        hit = any(det.scan(ctx, s, snap) is not None for s in samples)
        (caught if hit else missed).append(entity)
        print(f"  {'HIT ' if hit else 'MISS'}  {entity}")
    print("-" * 68)
    print(f"covered: {len(caught)}/{len(_SAMPLES)}   gaps: {missed}")

    # Optional zero-shot NER pass over the corpus (only if gliner is installed).
    try:
        from gliner import GLiNER  # noqa: F401
        _gliner_scan()
    except Exception:
        print("\n(gliner not installed — skipping zero-shot corpus scan; the curated")
        print(" diff above is the dependency-light gap signal.)")
    return 0


def _gliner_scan() -> None:
    from gliner import GLiNER
    from tests.eval.corpus_loader import load_corpus
    labels = ["Indian PAN", "Aadhaar number", "IBAN", "SWIFT code", "account number",
              "credit card number", "email", "passport number", "tax file number"]
    model = GLiNER.from_pretrained("urchade/gliner_small-v2.1")
    found: dict[str, int] = {}
    for e in load_corpus()[:120]:
        for ent in model.predict_entities(e.prompt, labels, threshold=0.5):
            found[ent["label"]] = found.get(ent["label"], 0) + 1
    print("\nGLiNER entity types found in corpus:", dict(sorted(found.items())))


if __name__ == "__main__":
    raise SystemExit(main())
