from tlslab.experiment_matrix import plan


def test_e6_600_policy_observations_expected():
    plans = plan("E6")
    assert len(plans) == 120  # 24 distinct scenarios x 5 repetitions
    assert len(plans)*5 == 600
    assert {(x["status"],x["stapling"],x["freshness"]) for x in plans}
