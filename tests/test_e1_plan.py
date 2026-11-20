from tlslab.experiment_matrix import plan
from tlslab.probe_suite import probe_catalogue


def test_e1_has_528_probe_runs():
    assert len(plan("E1"))==24
    assert len(probe_catalogue())==22
    assert len(plan("E1"))*len(probe_catalogue())==528
