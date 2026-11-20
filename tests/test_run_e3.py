import pytest
from tlslab.run_e3 import AEAD, fork_rows, ABLATIONS


def test_jmh_per_fork_scores_are_preserved():
    row = {"suite":"TLS_AES_128_GCM_SHA256","size":1024,"platform":"SunJCE"}
    raw={"params":{"size":"1024","provider":"SunJCE"},
         "primaryMetric":{"scoreUnit":"ops/s","rawData":[[100.,200.],[300.,500.]]}}
    out=fork_rows(raw,row)
    assert len(out)==2
    assert out[0]["ops_per_second"]==150
    assert out[1]["ops_per_second"]==400
    assert out[0]["wall_ns_per_byte"]>0 and out[0]["cpu_ns_per_byte"] is None


def test_missing_forks_rejected():
    with pytest.raises(ValueError):
        fork_rows({"primaryMetric":{"scoreUnit":"ops/s","rawData":[]}},
                  {"suite":"TLS_AES_128_GCM_SHA256","size":64,"platform":"SunJCE"})


def test_ablations_apply_only_to_sunjce_profiles():
    assert "A4" in ABLATIONS and "A5" in ABLATIONS
    assert all(AEAD.values())
