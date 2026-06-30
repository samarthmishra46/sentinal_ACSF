"""Contract tests for policy snapshot models."""

from __future__ import annotations

from datetime import datetime, timezone

from app.policy.models import Snapshot, policy_for


def _snap() -> Snapshot:
    return Snapshot(
        version="v1.0",
        created_at=datetime.now(timezone.utc),
        catalog={"R-01": {"policy_id": "P7", "title": "KYC artefacts"}},
    )


def test_policy_for_returns_catalog_entry() -> None:
    assert policy_for(_snap(), "R-01") == {"policy_id": "P7", "title": "KYC artefacts"}


def test_policy_for_missing_rule_returns_none() -> None:
    assert policy_for(_snap(), "R-99") is None


def test_policy_for_none_rule_id_returns_none() -> None:
    assert policy_for(_snap(), None) is None


def test_empty_snapshot_has_version() -> None:
    assert Snapshot.empty().version == "empty"
