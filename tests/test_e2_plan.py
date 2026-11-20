from tlslab.experiment_matrix import plan


def test_e2_twenty_four_cells_and_1200_handshakes():
    cases=plan("E2")
    assert len(cases)==24
    assert len(cases)*50==1200
    assert len({(x["provider"],x["suite"],x["group"]) for x in cases})==24
