# Sentinel ACSF

A FastAPI-based policy enforcement point (PEP) with audit and monitoring stubs.

## Install

Use the local package in editable mode:

```powershell
python -m pip install -e .
```

Install audit dependencies when needed:

```powershell
python -m pip install -r requirements-audit.txt
```

## Run

Start the FastAPI server with Uvicorn:

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Check health:

```powershell
curl http://127.0.0.1:8000/health
```

## Test

Run the existing pytest test suite:

```powershell
pytest
```

## Configuration

The app reads runtime values from environment variables:

- `DB_URL` - audit database URL, defaults to SQLite at `audit.db`
- `LATENCY_BUDGET_MS` - request latency budget in milliseconds, default `200`
- `SLACK_WEBHOOK` - Slack webhook URL for future escalation alerts
- `POLICY_BUNDLE_PATH` - policy bundle path, default `policies/v1`
