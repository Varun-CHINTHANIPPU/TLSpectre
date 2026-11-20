from collections import Counter
import pytest
from tlslab.experiment_matrix import (
    plan, e6_conditions, e4_conditions, block_order,
)


def test_matrix_sizes_and_reproducibility():
    assert [len(plan(e)) for e in ("E1","E2","E3","E4","E5","E6","E7")] == [
        24,24,360,240,160,120,180
    ]
    assert len(e4_conditions()) == 12
    assert block_order(e4_conditions(), 99) == block_order(e4_conditions(), 99)


def test_revocation_scenarios_are_unique():
    conditions = e6_conditions()
    assert len(conditions) == 24
    assert len({tuple(sorted(c.items())) for c in conditions}) == 24
    assert Counter(c["stapling"] for c in conditions) == {"off": 8, "on": 16}


def test_each_e4_block_has_all_conditions():
    for block in range(1,21):
        cells = [(c["configuration"], c["suite"]) for c in plan("E4") if c["block"] == block]
        assert len(set(cells)) == 12


def test_bad_experiment_rejected():
    with pytest.raises(ValueError):
        plan("NOT_E")
