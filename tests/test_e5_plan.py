from tlslab.experiment_matrix import plan


def test_full_e5_plan_has_160_cells_and_four_groups():
    cells = plan("E5")
    assert len(cells)==160
    assert len(set(c["group"] for c in cells))==4
    assert {c["rtt_ms"] for c in cells}=={0,50}
    assert len({(c["provider"],c["group"],c["rtt_ms"]) for c in cells})==16
