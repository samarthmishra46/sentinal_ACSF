# Nikhil — Day 2 Deliverables: Real Secrets Detector (R-07) + Audit Hardening

**Sprint:** Sentinel · Day 2 (Logic Day).
**My role:** Secrets Detector + Audit Log.
**Built against:** the team's real contracts on the `devlop` branch of
`samarthmishra46/sentinal_ACSF` (Samarth's `decision.py`, Sneha's `BaseDetector`,
Ryan's `audit_hook.py`). Built **locally**, not pushed yet.

---

## 1. What Day 2 asked of me

From the sprint plan, my Day-2 card was **"Secrets Detector (Real) + Audit Log (Real)"**:
regex + entropy + bloom credential scanner for **R-07** (stage 4), finalize the
async audit logger, and prove "paste a credential → R-07 fires → STOP".

## 2. What I built (my files only)

| File | Purpose |
|---|---|
| `app/pdp/detectors/secrets.py` | **Real R-07 detector.** Fills the stub (Owner: Nikhil), implements Sneha's `BaseDetector` (`stage_name="secrets_scanner"`, `stage_order=4`), returns Samarth's `Signal(rule_id="R-07", Disposition.STOP, …)`. |
| `tests/test_secrets_detector.py` | 20 tests — fires on every credential class, stays quiet on the policy's "does NOT fire" cases. |
| `app/audit/models.py` (hardened) | `from_decision` now maps onto the team's **real** `Decision`/`Signal`/`RequestContext`. |
| `tests/audit/test_models.py` (+2 tests) | Prove `from_decision` against faithful replicas of Samarth's + Anamika's types. |
| `docs/DAY2_INTEGRATION.md` | The one-line diffs teammates apply (factory registration, Ryan's sink swap, the identity-import fix). |

## 3. The secrets detector — how it works

Cheapest-first, mirroring the PII detector's structure:

1. **Bloom pre-filter** — dependency-free `_BloomFilter` over candidate tokens,
   seeded with public burned/example keys (e.g. AWS's `AKIA…EXAMPLE`). O(1) fast
   path for known leaks; empty of real secrets so it adds **zero** false positives.
2. **Structured regex** — labelled patterns: DB URIs with passwords
   (`postgres://u:p@host`), AWS `AKIA…`, Stripe `sk_live_`, Google `AIza…`,
   GitHub `ghp_…`, Slack `xox…`, Bearer/JWT, PEM `-----BEGIN … PRIVATE KEY-----`,
   and `.env` assignments (`DB_PASSWORD=…`).
3. **Shannon entropy fallback** — 40+ char mixed-alphanumeric tokens the patterns
   miss (per the policy's "40+ characters of mixed alphanumeric").

**False-positive guards** (the policy's "does NOT fire" list): placeholder values
(`<password>`, `your_key`, `xxx…`), `.env.example` templates, and general-knowledge
questions ("what format is an AWS key?", "how do I configure the connection pool?").
The detector **never raises** (per `BaseDetector`); any error returns `None`.

Emitted signal:
```python
Signal(detector="secrets_scanner", rule_id="R-07", disposition=Disposition.STOP,
       reason="Credential detected: <type>. Reference secrets by vault path …",
       confidence=…, metadata={"owasp_id":"LLM02","atlas_id":"AML.T0024",
                               "severity":"HIGH","secret_type":<type>})
```

## 4. Audit hardening (my `models.py`)

`from_decision` now reads the team's real object shapes (all verified by tests):
- `Decision.disposition` (IntEnum) → decision string
- `Decision.decisive_signal.rule_id` → `rule_triggered` (Decision has no rule field)
- `[s.detector for s in signals]` → `signals`
- `RequestContext.owned_services[0]` → `service`
- `Decision.policy_version` → `policy_version`

## 5. How to run / verify (all local, no external services)

```bash
python -m pytest tests/ -q          # -> 44 passed
python -m pytest tests/test_secrets_detector.py -q   # the R-07 detector alone
```

- The **canonical red-team prompt RT-06** (`postgres://lexaml_admin:s3cretP4ss@…`)
  → `SecretsDetector.scan` returns `STOP` / `R-07`. ✅
- Tests use the team's proven `sys.modules`-stub pattern, so they pass **even
  though `app/identity/` isn't on devlop yet**.

## 6. What I did NOT touch (propose-only, per your call)

- `app/pdp/factory.py` (Samarth) — one-line registration, see `docs/DAY2_INTEGRATION.md`.
- `app/pep/audit_hook.py` (Ryan) — the `default_sink()` adapter, see same doc.
- The `app/identity` import break (Anamika/Sneha) — flagged, not fixed by me.

## 7. Still pending for full Day-2 "runs on devlop"

1. Merge my `app/audit/` package to devlop (unblocks Ryan's sink) — waiting on your go-ahead.
2. Teammates apply the two one-liners above.
3. The identity-import break gets fixed so the pipeline can load detectors.
