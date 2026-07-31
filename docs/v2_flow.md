# Sentinel — how a request flows

Every stage, in order, with what it checks and what it can return. Cheapest checks run
first and a **STOP short-circuits the rest**, so the expensive semantic work only ever sees
prompts that survived everything cheap.

`★NEW` marks what V2 added. All new tiers ship **switched off** behind an env flag.

---

## The whole path

```
                          ┌─────────────────────────┐
                          │   USER TYPES A PROMPT   │
                          └────────────┬────────────┘
                                       ▼
                          ┌─────────────────────────┐
                          │  PEP INGRESS            │
                          │  POST /v1/chat          │
                          └────────────┬────────────┘
                                       ▼
╔══════════════════════════════════════════════════════════════════════════╗
║                    INPUT PIPELINE  (cheapest first)                      ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  ┌───────────────────────────────┐                                       ║
║  │ 1 · NORMALIZE          <1ms   │  whitespace, zero-width, homoglyphs   ║
║  └───────────────┬───────────────┘                                       ║
║                  ▼                                                       ║
║  ┌───────────────────────────────┐                                       ║
║  │ 2 · IDENTITY           <1ms   │  role/tenant/owned_services from      ║
║  └───────────────┬───────────────┘  EIM TOKEN — never from prompt text   ║
║                  ▼                                                       ║
║  ┌───────────────────────────────┐                                       ║
║  │ 3 · CEDAR AUTHZ      O(1)     ├──── not permitted ──► STOP  R-AUTH    ║
║  └───────────────┬───────────────┘                                       ║
║                  ▼ permitted                                             ║
║  ┌───────────────────────────────┐                                       ║
║  │ 4 · SECRETS           regex   ├──── hit ────────────► STOP  R-07      ║
║  └───────────────┬───────────────┘      db URIs, AWS keys, tokens        ║
║                  ▼                                                       ║
║  ┌───────────────────────────────┐                                       ║
║  │ 5 · INJECTION (phrases)       ├──── hit ────────────► STOP  R-06      ║
║  └───────────────┬───────────────┘      ~40 literal jailbreak phrases    ║
║                  ▼                                                       ║
║  ┌───────────────────────────────┐                                       ║
║  │ 6 · PII               regex   ├──── hit ────────────► STOP  R-01      ║
║  └───────────────┬───────────────┘  TFN passport Medicare licence        ║
║                  ▼                  name+DOB address PAN Aadhaar         ║
║                                     IBAN SWIFT SSN card email            ║
║  ┌───────────────────────────────┐                                       ║
║  │ 7 · COMPLIANCE RULES          ├──── hit ────────────► STOP / ESCALATE ║
║  └───────────────┬───────────────┘  verb + object must BOTH match        ║
║                  ▼                  R-02 R-03 R-04 R-05 R-09             ║
║  ╔═══════════════════════════════╗                                       ║
║  ║ 8 · SEMANTIC LAYER  ★NEW      ║  ~40ms · 52ms p95                     ║
║  ║        (expanded below)       ╠──── hit ────────────► STOP / ESCALATE ║
║  ╚═══════════════┬═══════════════╝                                       ║
║                  ▼                                                       ║
║  ┌───────────────────────────────┐                                       ║
║  │ 9 · DESTRUCTIVE OPS           ├──── hit ────────────► ESCALATE R-21   ║
║  └───────────────┬───────────────┘  delete/drop + customers/records      ║
║                  ▼                                                       ║
║  ╔═══════════════════════════════╗                                       ║
║  ║ 10 · BEHAVIOUR      ★NEW      ║  looks ACROSS requests:               ║
║  ║                               ╠──── anomaly ────────► ESCALATE R-22   ║
║  ╚═══════════════┬═══════════════╝  queries/hr · distinct customers ·    ║
║                  │                  off-owned svc · off-hours · streak   ║
╚══════════════════┼═══════════════════════════════════════════════════════╝
                   ▼
        ┌──────────────────────┐
        │  COMBINE             │   strictest wins  =  max()
        │  ALLOW=0 ESC=1 STOP=2│   empty set → ESCALATE (fail-closed)
        └──────────┬───────────┘
                   │
      ┌────────────┼────────────┐
      ▼            ▼            ▼
   ┌──────┐   ┌─────────┐   ┌───────┐
   │ STOP │   │ESCALATE │   │ ALLOW │
   └───┬──┘   └────┬────┘   └───┬───┘
       │           │            ▼
       │           │   ┌──────────────────┐
       │           │   │ BACK-END AI      │
       │           │   │ generate(prompt, │
       │           │   │          ctx)    │
       │           │   └────────┬─────────┘
       │           │            ▼
       │           │  ╔══════════════════════════════════════╗
       │           │  ║        OUTPUT SCANNER                ║
       │           │  ║  O1 normalize                        ║
       │           │  ║  O2 PII / secrets leak               ║
       │           │  ║  O3 unsafe code (bypass, exploit)    ║
       │           │  ║  O4 alignment (sys-prompt, DAN)      ║
       │           │  ║  O5 EXCHANGE ★NEW answer vs prompt   ║
       │           │  ╚══════════════┬═══════════════════════╝
       │           │                 │
       │           │      ┌──────────┼──────────┐
       │           │      ▼          ▼          ▼
       │           │   BLOCK      REDACT      PASS
       │           │      │          │          │
       │           │      │          └────┬─────┘
       │           │      │               ▼
       │           │      │      ┌─────────────────┐
       │           │      │      │ ANSWER DELIVERED│
       │           │      │      └────────┬────────┘
       ▼           ▼      ▼               ▼
   ┌──────────────────────────────────────────────┐
   │              AUDIT LOG                       │
   │  decision · rule_triggered · policy_triggered│
   │  reason · prompt_hash(sha256) · user_id      │
   │  role · service · latency_ms · signals       │
   │  policy_version · timestamp · request_id     │
   └──────────────────────────────────────────────┘
                        │
                        ▼ (ESCALATE only)
   ┌──────────────────────────────────────────────┐
   │   HUMAN REVIEWER  ──►  labelled example      │
   │        ▲                      │              │
   │        │                      ▼              │
   │  ┌─────┴──────┐      ┌────────────────┐      │
   │  │ Stage 8    │◄─────┤ RETRAIN (39KB) │      │
   │  └────────────┘      └────────▲───────┘      │
   │                               │              │
   │            catalog.yaml ──► generate ──► mutate ──► spot-check
   └──────────────────────────────────────────────┘
              THE FLYWHEEL: rules become training data
```

**Fail-closed everywhere.** Unknown user → STOP. A stage throws → ESCALATE. No verdicts at
all → ESCALATE. Audit unreachable → ESCALATE. Silence is never treated as approval.

---

## Stage 8 expanded — embed once, use twice

The expensive part is turning the prompt into numbers. Do it **once**, cache it, and both
consumers read the same vector — which is why the second one is nearly free.

```
              prompt survived stages 1-7
                        │
                        ▼
        ┌───────────────────────────────────┐
        │  EMBED ONCE                       │
        │  MiniLM → 384 numbers · memoized  │   ~40ms
        └───────────┬───────────┬───────────┘
                    │           │        (same cached vector)
        ┌───────────┘           └───────────┐
        ▼                                   ▼
┌───────────────────┐            ┌──────────────────────┐
│  kNN SIMILARITY   │            │  INTENT CLASSIFIER   │
│  vs 584 attacks   │            │  softmax(W·x+b)      │
└─────────┬─────────┘            └──────────┬───────────┘
          │                                 │  ~0ms extra
    ┌─────┴─────┬──────────┐          ┌─────┴─────┬──────────┐
    ▼           ▼          ▼          ▼           ▼          ▼
  ≥0.80    0.72-0.80     <0.72     ≥0.70     0.45-0.70    benign
    │           │          │          │           │        <0.45
    ▼           └─────┬────┘          ▼           ▼          ▼
  STOP                │          rule's own   ESCALATE     pass
  cites               │          level:        (softened)
  attack              │          R-02/03/09
   ID                 ▼           → STOP
      ┌──────────────────────┐    R-05
      │ DeBERTa RECHECK      │     → ESCALATE
      │ ON by default ~340ms │
      │ ≥0.90 STOP           │
      │ ≥0.50 ESCALATE       │
      └──────────────────────┘
```

**Why the recheck.** Similarity only recognises paraphrases of attacks *already in the
bank*, so "far from every known attack" is not evidence of being benign — it is the gap
novel wording walks through. Everything the kNN tier does not STOP outright, band or
apparent-pass alike, gets a second opinion from DeBERTa. Only a tier-1 STOP skips it, so
in practice nearly every surviving prompt pays the ~340ms: recall bought with latency.

**Ceiling rule.** Similarity says *which* attack; the catalog says *how strict* it is. A
perfect 1.00 match to an ESCALATE-class rule (R-05 bulk, R-08 cross-org) still only
escalates — never STOP.

**Why cite a neighbour.** A match reports *"0.94 similar to known attack RT-04"* — a sentence
an auditor can follow. A bare confidence score of 0.87 explains nothing.

**New attack on Monday** → add one bank entry → protected that afternoon. No retraining, no
redeploy.

---

## The three verdicts

| Verdict | Value | What happens | Does the AI see the prompt? |
|---|---|---|---|
| ALLOW | 0 | passes through to the assistant | yes |
| ESCALATE | 1 | held for a human; becomes a labelled example | not yet |
| STOP | 2 | refused, rule + policy cited | never |

Higher number = stricter, so combining is a plain `max()` and can't be got wrong.

---

## Stage reference

| # | Stage | Catches | Emits | Cost |
|---|---|---|---|---|
| 1 | normalize | obfuscation | — | <1ms |
| 2 | identity | — | — | <1ms |
| 3 | Cedar authz | unpermitted identity | STOP R-AUTH | O(1) bitmask |
| 4 | secrets | connection strings, AWS keys, tokens | STOP R-07 | regex |
| 5 | injection (phrase) | literal jailbreak phrases | STOP R-06 | Aho-Corasick |
| 6 | PII | AU IDs + PAN, Aadhaar, IBAN, SWIFT, SSN, card, email | STOP R-01 | regex |
| 7 | compliance rules | SMR/TTR, bypass, attack, bulk, audit-manip | STOP/ESCALATE | two-part match |
| 8 | **semantic ★** | paraphrased attacks | STOP/ESCALATE | ~40ms, 52ms p95 |
| 9 | destructive ops | delete/drop + customer objects | ESCALATE R-21 | regex |
| 10 | **behaviour ★** | patterns across requests | ESCALATE R-22 | in-memory |

Order is load-bearing: a pasted password STOPs at stage 4 in microseconds and never reaches
the 40ms semantic layer.

---

## Running it

```bash
./run_v2.sh demo    # see it catch bulk assembly + a paraphrased bypass
./run_v2.sh gate    # 13-prompt red-team gate, all tiers on
./run_v2.sh eval    # the adversarial numbers
./run_v2.sh serve   # API + web UI on localhost:8000
./run_v2.sh test    # full suite (tiers off, like CI)
```

Flags: `KNN_ENABLED` · `INTENT_ML_ENABLED` · `BEHAVIOUR_ENABLED` default **false**;
`ML_DETECTOR_ENABLED` defaults **true** (the DeBERTa recheck; set it false for the fast
deterministic path — the deploy image does). Measured results in [v2_eval_results.md](v2_eval_results.md).
