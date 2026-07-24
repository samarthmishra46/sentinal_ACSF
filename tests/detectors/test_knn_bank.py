"""Unit tests for the kNN attack bank — pure numpy, no model download."""

from __future__ import annotations

import numpy as np
import pytest

from app.pdp.knn.bank import AttackBank, BankEntry, load_bank, save_bank


def _entry(i: int, rule: str = "R-06") -> BankEntry:
    return BankEntry(id=f"A-{i}", text=f"attack {i}", rule_id=rule, source="corpus")


def _norm(v: np.ndarray) -> np.ndarray:
    return v / np.linalg.norm(v)


def test_nearest_returns_closest_by_cosine() -> None:
    # Three orthonormal-ish rows; a query aligned with row 1 must return it.
    matrix = np.vstack([_norm(np.array([1.0, 0.0, 0.0])),
                        _norm(np.array([0.0, 1.0, 0.0])),
                        _norm(np.array([0.0, 0.0, 1.0]))]).astype(np.float32)
    bank = AttackBank(matrix, [_entry(0, "R-01"), _entry(1, "R-03"), _entry(2, "R-05")])
    sim, entry = bank.nearest(_norm(np.array([0.1, 0.95, 0.05])).astype(np.float32))
    assert entry.rule_id == "R-03"
    assert 0.9 < sim <= 1.0


def test_empty_bank_returns_none() -> None:
    empty = AttackBank(np.zeros((0, 3), dtype=np.float32), [])
    assert empty.nearest(np.array([1.0, 0.0, 0.0], dtype=np.float32)) is None


def test_row_count_mismatch_rejected() -> None:
    with pytest.raises(ValueError):
        AttackBank(np.zeros((2, 3), dtype=np.float32), [_entry(0)])


def test_save_then_load_roundtrip(tmp_path, monkeypatch) -> None:
    from app.config import settings
    monkeypatch.setattr(settings, "KNN_BANK_PATH", str(tmp_path / "bank"))
    matrix = np.vstack([_norm(np.array([1.0, 0.0])), _norm(np.array([0.0, 1.0]))]).astype(np.float32)
    rows = [{"id": "A-0", "text": "x", "rule_id": "R-06", "source": "redteam"},
            {"id": "A-1", "text": "y", "rule_id": "R-03", "source": "corpus"}]
    save_bank(matrix, rows)
    bank = load_bank()
    assert bank is not None and len(bank) == 2
    sim, entry = bank.nearest(np.array([1.0, 0.0], dtype=np.float32))
    assert entry.id == "A-0" and sim == pytest.approx(1.0, abs=1e-5)


def test_missing_bank_loads_as_none(tmp_path, monkeypatch) -> None:
    from app.config import settings
    monkeypatch.setattr(settings, "KNN_BANK_PATH", str(tmp_path / "does_not_exist"))
    assert load_bank() is None
