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
real pipeline and asserts each verdict, plus a latency gate that asserts the input
pipeline (stages 1–7) stays well under the 150 ms budget.

To see the per-stage latency breakdown (mean / p50 / p95 / max):

```bash
python -m tests.eval.latency
```

## Configuration

The app reads runtime values from environment variables:

- `DB_URL` — audit database URL, defaults to SQLite at `audit.db`
- `LATENCY_BUDGET_MS` — request latency budget in milliseconds, default `200`
- `SLACK_WEBHOOK` — Slack webhook URL for future escalation alerts
- `POLICY_BUNDLE_PATH` — policy bundle path, default `policies/v1`

## V2 Backlog

V1 ships input Stages 1–7, output O1–O4, the STOP/REDACT/ESCALATE/ALLOW outcomes,
rules R-01…R-09, the SQLite audit log, and the 13-prompt red-team suite. Items
consciously deferred to V2 — multi-turn context (R-10), ALLOW+CONSTRAIN (R-11),
behavioural profiling (R-12/R-13), real EIM identity, reviewer UI, HA deployment,
audit hash chain, a full AI intent classifier, a real LLM backend, and a chat
frontend — are documented with rationale in **[docs/v2_backlog.md](docs/v2_backlog.md)**.
