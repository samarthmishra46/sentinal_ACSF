"""Contract tests for policy snapshot models."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.policy.models import Snapshot, policy_for

BUNDLE = Path(__file__).resolve().parents[1] / "policies" / "v1"


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


def test_from_bundle_compiles_real_policy() -> None:
    snap = Snapshot.from_bundle(BUNDLE)
    assert snap.version == "v1.0"
    assert "R-01" in snap.catalog            # catalog keyed by rule id
    assert snap.catalog["R-01"]["disposition"] == "STOP"
    assert len(snap.cedar_text) > 0          # authz.cedar loaded


def test_from_bundle_missing_dir_raises() -> None:
    with pytest.raises(Exception):
        Snapshot.from_bundle(BUNDLE / "does-not-exist")
