from tlslab.experiment_matrix import plan
from collections import Counter


def test_e7_scenarios_are_block_randomized():
    rows = plan("E7",blocks=30)
    assert len(rows)==180
    assert set((r["stapling"],r["rtt_ms"]) for r in rows)=={
        ("off",0),("off",50),("warm",0),("warm",50),("cold",0),("cold",50)}
    assert Counter(r["block"] for r in rows)=={i:6 for i in range(1,31)}
