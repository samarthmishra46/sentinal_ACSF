# Sentinel ACSF

A FastAPI-based policy enforcement point (PEP) that screens every prompt through a
staged policy-decision pipeline (authorization + secret/injection/PII/intent
detectors), with an append-only audit log and monitoring stubs.

## Install

Editable install of the base package:

```bash
python -m pip install -e .
```

For development (test runner + HTTP test client):

```bash
python -m pip install -e ".[dev]"
```

Optional extras when needed: `.[audit]` (PostgreSQL), `.[detectors]` (Presidio /
bloom filter).

## Run

Start the FastAPI server with Uvicorn:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Check health:

```bash
curl http://127.0.0.1:8000/health
```

## Test

```bash
pytest
```

The full suite runs clean in one shot (no `--ignore` needed). It includes the
red-team gate (`tests/eval/`), which fires all 13 adversarial prompts through the
real pipeline and asserts each verdict.

## Configuration

The app reads runtime values from environment variables:

- `DB_URL` — audit database URL, defaults to SQLite at `audit.db`
- `LATENCY_BUDGET_MS` — request latency budget in milliseconds, default `200`
- `SLACK_WEBHOOK` — Slack webhook URL for future escalation alerts
- `POLICY_BUNDLE_PATH` — policy bundle path, default `policies/v1`

## V2 Backlog — Deferred from V1

V1 ships input Stages 1–7, output O1–O4, the STOP/REDACT/ESCALATE/ALLOW outcomes,
rules R-01…R-09, the SQLite audit log, and the 13-prompt red-team suite. The
following are intentionally deferred to V2:

| Item | Why deferred | Ref |
|------|--------------|-----|
| Multi-turn / session context | Needs a conversation store (Redis tier); no history in V1 | R-10 · `pdp/session.py` |
| ALLOW + CONSTRAIN outcome | Response constrainer (post-model gate O5) not built | R-11 · `pdp/constrainer.py` |
| Automated system behavioural profiling | Needs a behavioural baseline (data that doesn't exist yet) | R-12 · `monitoring/profiler.py` |
| Adversary behavioural detection | Same cold-start baseline dependency | R-13 · `monitoring/behaviour.py` |
| Real EIM identity | Mocked (5 seeded users) in V1 | `identity/eim_client.py` |
| Reviewer UI | V1 escalation is Slack notification only | — |
| HA deployment | V1 is a single server | — |
| SHA-256 hash chain on audit log | V1 stores per-record hashes, not a chain | `audit/` |
| Full AI intent classifier | V1 uses rule-based intent only (AI-judging-AI is a new attack surface) | Stage 9 |
| Real LLM backend | V1 uses a stub assistant behind a clean interface | `assistant/` |
| Chat frontend | V1 is API-only (`/v1/chat`) | — |

Note: R-12/R-13 land in the monitoring layer (`app/monitoring/`), extending V1's
signal counters into behavioural baselining.
