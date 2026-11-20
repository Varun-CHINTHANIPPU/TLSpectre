from tlslab.experiment_matrix import plan
from tlslab.env import pinned
from tlslab.netns import exec_in, NAMES
from tlslab.evidence import sha256_file


def test_argv_safe_affinity():
    assert pinned(["java", "-version"], [3, 7]) == ["taskset","-c","3,7","java","-version"]


def test_namespaces_reject_unknown_names():
    import pytest
    with pytest.raises(ValueError):
        exec_in("localhost", ["true"])
    assert len(NAMES) == 3


def test_run_plans_have_experiment_ids():
    for name in ("E1","E2","E3","E4","E5","E6","E7"):
        assert {r["experiment"] for r in plan(name)} == {name}


def test_parquet_preserves_late_failure_columns(tmp_path):
    import pandas as pd
    from tlslab.evidence import to_parquet
    target=tmp_path/"results.parquet"
    to_parquet([{"condition":"P1","status":"MEASURED","goodput":42.0},
                {"condition":"P2","status":"FAILED","error":"handshake failed"}],target)
    loaded=pd.read_parquet(target)
    assert "error" in loaded.columns
    assert loaded.loc[1,"error"]=="handshake failed"
    assert pd.isna(loaded.loc[0,"error"])
