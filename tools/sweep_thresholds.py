"""Held-out threshold sweep for the kNN similarity tier (Phase 2).

The production attack bank contains every known attack, so evaluating against the
same corpus that built it would self-match at 1.0 and report a fake 100%. This
tool measures **generalisation** honestly:

  * BANK  = malicious originals + their seed-0 mutations (what ships).
  * EVAL  = seed-1 mutations of the same malicious parents — *held-out paraphrases*
            the bank has never seen verbatim — plus the benign corpus (never in the
            bank, so no leakage there).

For each (KNN_STOP_THRESHOLD, KNN_BAND_LOW) it reports, on held-out data:
  * detection — held-out malicious paraphrases with sim >= band_low (kNN objects)
  * FP(band)  — benign with sim >= band_low (pessimistic: band escalates)
  * FP(stop)  — benign with sim >= stop     (realistic: band gets a classifier
                second opinion that usually clears a benign near-miss)
  * band load — fraction of ALL traffic landing in [band_low, stop) → classifier calls

Pick the pair that maximises detection subject to FP(stop) <= the rules+ml baseline
and band load < 5%. Writes nothing; prints a table. Run:

    PYTHONPATH=. python tools/sweep_thresholds.py
"""

from __future__ import annotations

import numpy as np

from app.pdp.knn.bank import AttackBank, BankEntry
from app.pdp.knn.embed import embed, embedding_available
from tests.eval.corpus_loader import load_benign, load_malicious
from tests.eval.harness import _load_prompts
from tests.eval.mutations import generate

BANK_SEED = 0
EVAL_SEED = 1
PER_STRATEGY = 3


def _malicious_parents() -> list[tuple[str, str, str]]:
    """(id, prompt, rule) for red-team + curated malicious originals."""
    out: list[tuple[str, str, str]] = []
    for e in _load_prompts():
        if e.get("expected_decision", "ALLOW") != "ALLOW":
            out.append((e["id"], " ".join(e["prompt"].split()),
                        e.get("expected_rule", "R-06")))
    for c in load_malicious():
        out.append((c.id, c.prompt, c.rule or "R-06"))
    return out


def _build_bank(parents) -> AttackBank:
    rows, texts, seen = [], [], set()

    def add(id_, text, rule, source):
        norm = " ".join(text.split())
        if norm and norm not in seen:
            seen.add(norm)
            rows.append(BankEntry(id=id_, text=norm, rule_id=rule, source=source))
            texts.append(norm)

    for pid, prompt, rule in parents:
        add(pid, prompt, rule, "original")
        for m in generate(prompt, per_strategy=PER_STRATEGY, seed=BANK_SEED):
            add(f"{pid}:{m.strategy}", m.text, rule, "mutation")
    matrix = np.vstack([embed(t) for t in texts]).astype(np.float32)
    return AttackBank(matrix, rows)


def _held_out_malicious(parents) -> list[str]:
    """Seed-1 paraphrases (not in the seed-0 bank) — the generalisation test set."""
    bank_texts = set()
    for pid, prompt, _ in parents:
        for m in generate(prompt, per_strategy=PER_STRATEGY, seed=BANK_SEED):
            bank_texts.add(m.text)
    evals = []
    for pid, prompt, _ in parents:
        for m in generate(prompt, per_strategy=PER_STRATEGY, seed=EVAL_SEED):
            if m.text not in bank_texts:  # only genuinely held-out paraphrases
                evals.append(m.text)
    return evals


def _benign_eval() -> list[str]:
    texts = []
    for e in load_benign():
        texts.append(e.prompt)
        for m in generate(e.prompt, per_strategy=PER_STRATEGY, seed=EVAL_SEED,
                          label_preserving_only=True):
            texts.append(m.text)
    return texts


def main() -> int:
    if not embedding_available():
        print('ERROR: embedding model unavailable. Install: pip install -e ".[ml]"')
        return 1

    parents = _malicious_parents()
    bank = _build_bank(parents)
    mal = _held_out_malicious(parents)
    ben = _benign_eval()
    print(f"bank={len(bank)}  held-out malicious={len(mal)}  benign eval={len(ben)}")

    mal_sims = np.array([bank.nearest(embed(t))[0] for t in mal])
    ben_sims = np.array([bank.nearest(embed(t))[0] for t in ben])
    n_all = len(mal_sims) + len(ben_sims)

    print(f"\nheld-out malicious sim: mean={mal_sims.mean():.3f} "
          f"p50={np.percentile(mal_sims,50):.3f} p10={np.percentile(mal_sims,10):.3f}")
    print(f"benign            sim: mean={ben_sims.mean():.3f} "
          f"p90={np.percentile(ben_sims,90):.3f} max={ben_sims.max():.3f}")

    # STOP@ = guaranteed kNN STOP (sim>=stop). This is the real detection floor for
    # compliance attacks, where the injection classifier in the band won't help.
    # detect(band) = sim>=band, achievable only if the band also blocks/escalates.
    print(f"\n{'stop':>5} {'band':>5} {'STOP@':>7} {'detect':>8} "
          f"{'FP(stop)':>9} {'FP(band)':>9} {'band load':>10}")
    print("-" * 62)
    for stop in (0.90, 0.85, 0.82, 0.80, 0.78, 0.75):
        for band in (0.72, 0.70, 0.68, 0.65):
            if band >= stop:
                continue
            stop_only = float((mal_sims >= stop).mean())
            detect = float((mal_sims >= band).mean())
            fp_band = float((ben_sims >= band).mean())
            fp_stop = float((ben_sims >= stop).mean())
            in_band = (((mal_sims >= band) & (mal_sims < stop)).sum()
                       + ((ben_sims >= band) & (ben_sims < stop)).sum())
            load = in_band / n_all
            flag = "  <<" if (stop_only >= 0.85 and fp_stop <= 0.05 and load < 0.05) else ""
            print(f"{stop:5.2f} {band:5.2f} {stop_only:7.1%} {detect:8.1%} "
                  f"{fp_stop:9.1%} {fp_band:9.1%} {load:10.1%}{flag}")
    print("\n<< = STOP@>=85% (compliance-safe floor) AND FP(stop)<=5% AND band load<5%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
