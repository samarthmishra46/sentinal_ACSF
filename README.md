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

> Note: until the detector test files stop manipulating `sys.path`, run the full
> suite with `pytest --ignore=tests/smoke.py --ignore=tests/test_detectors.py`
> (those two pass on their own).

## Configuration

The app reads runtime values from environment variables:

- `DB_URL` — audit database URL, defaults to SQLite at `audit.db`
- `LATENCY_BUDGET_MS` — request latency budget in milliseconds, default `200`
- `SLACK_WEBHOOK` — Slack webhook URL for future escalation alerts
- `POLICY_BUNDLE_PATH` — policy bundle path, default `policies/v1`
