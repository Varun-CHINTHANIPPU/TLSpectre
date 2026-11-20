import json
from pathlib import Path
import pandas as pd
import pytest
from tlslab.analysis.artifacts import (
    artifact_figure,artifact_table,InsufficientEvidence
)


def test_no_unverified_data_can_be_plotted(tmp_path):
    folder=tmp_path/"data/raw/E4/sample"
    folder.mkdir(parents=True)
    pd.DataFrame([{"validated":False, "condition":"P1","suite":"AES",
                   "mib_per_second":200}]).to_parquet(folder/"results.parquet")
    (folder/"manifest.json").write_text(json.dumps({
        "experiment":"E4","disposition":"COMPLETE","metadata":{"pilot":False}}))
    with pytest.raises(InsufficientEvidence):
        artifact_figure("F3",root=tmp_path)


def test_pilot_rows_are_excluded(tmp_path):
    folder=tmp_path/"data/raw/E4/sample"
    folder.mkdir(parents=True)
    pd.DataFrame([{"validated":True,"condition":"P1","suite":"AES",
                   "mib_per_second":200}]).to_parquet(folder/"results.parquet")
    (folder/"manifest.json").write_text(json.dumps({
        "experiment":"E4","disposition":"COMPLETE","metadata":{"pilot":True}}))
    with pytest.raises(InsufficientEvidence):
        artifact_figure("F3",root=tmp_path)


def test_table_t2_is_design_not_inferred_observation():
    from tlslab.analysis.artifacts import ROOT
    result=artifact_table("T2",root=ROOT)
    frame=pd.read_csv(result)
    assert len(frame)==11
    assert set(["P1","P2","A4","A5","B3"]).issubset(set(frame["configuration"]))
    result.unlink()


def test_t1_reports_unverified_environment_explicitly(tmp_path):
    folder=tmp_path/"data/raw/E2/one-complete-run"
    folder.mkdir(parents=True)
    (folder/"manifest.json").write_text(json.dumps({
        "experiment":"E2","disposition":"COMPLETE",
        "metadata":{"pilot":False},"git_sha":"example",
        "java":"OpenJDK 27","openssl":"OpenSSL 3",
        "nginx":"nginx","tshark":"tshark",
        "hardware":{"cpu_model":"fixture CPU","cpu_count":8}
    }))
    table=artifact_table("T1",root=tmp_path)
    frame=pd.read_csv(table)
    assert len(frame)==1
    assert frame.loc[0,"experiment"]=="E2"
    assert frame["environment_independently_validated"].eq(False).all()
    assert "independently verify" in frame.loc[0,"source"]


def test_t1_rejects_pilot_only_environment(tmp_path):
    folder=tmp_path/"data/raw/E2/pilot"
    folder.mkdir(parents=True)
    (folder/"manifest.json").write_text(json.dumps({
        "experiment":"E2","disposition":"COMPLETE","metadata":{"pilot":True}
    }))
    with pytest.raises(InsufficientEvidence,match="COMPLETE non-pilot"):
        artifact_table("T1",root=tmp_path)
