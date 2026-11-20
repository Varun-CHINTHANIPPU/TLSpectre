"""E2-E6 audit rejects unmeasured data while handling E6 certificate status."""
import json

import pandas as pd
import pytest

from tlslab.analysis.audit_measurements import (
    audit_one, expected_keys, EvidenceAuditError)
from tlslab.experiment_matrix import plan


def test_expected_factor_cardinality():
    assert {x: len(expected_keys(x)) for x in ("E2","E3","E4","E5","E6")} == {
        "E2":24, "E3":360, "E4":240, "E5":160, "E6":600}


def e2_fixture(tmp_path):
    out=tmp_path/"data/raw/E2/run"
    out.mkdir(parents=True)
    frame=pd.DataFrame([{
        **row,"status":"MEASURED","validated":True,
        "n_verified":50,"n_expected":50,
        "verification_pass":1,"group_verified":True,
        "validation_failures":None
    } for row in plan("E2")])
    frame.to_parquet(out/"results.parquet")
    (out/"manifest.json").write_text(json.dumps({
        "experiment":"E2","metadata":{"pilot":False},"disposition":"COMPLETE",
        "git_sha":"synthetic"}))
    return out


def test_e2_evidence_audit_accepts_full_independent_matrix(tmp_path):
    output=audit_one("E2",e2_fixture(tmp_path))
    assert output["cells"]==24
    assert len(output["parquet_sha256"])==64
    assert "structural" in output["qualification"]


def test_e2_evidence_audit_rejects_missing_verification(tmp_path):
    out=e2_fixture(tmp_path)
    df=pd.read_parquet(out/"results.parquet")
    df.loc[0,"group_verified"]=False
    df.to_parquet(out/"results.parquet")
    with pytest.raises(EvidenceAuditError,match="E2:"):
        audit_one("E2",out)


def test_e2_evidence_audit_rejects_duplicate_matrix_cells(tmp_path):
    out=e2_fixture(tmp_path)
    df=pd.read_parquet(out/"results.parquet")
    df.loc[0,["provider","suite","group"]]=df.loc[1,["provider","suite","group"]]
    df.to_parquet(out/"results.parquet")
    with pytest.raises(EvidenceAuditError,match="duplicate"):
        audit_one("E2",out)


def test_e6_certificate_status_is_not_measurement_status(tmp_path):
    out=tmp_path/"E6"
    out.mkdir()
    cases=plan("E6")
    df=pd.DataFrame([{
        **row,"policy":policy,"validated":True,
        "outcome":"ACCEPT","matches_expectation":True,
        "staple_observed":row["stapling"]=="on"
    } for row in cases for policy in ("K1","K2","K3","K4","K5")])
    df.to_parquet(out/"results.parquet")
    (out/"manifest.json").write_text(json.dumps({
        "experiment":"E6","metadata":{"pilot":False},"disposition":"COMPLETE"}))
    result=audit_one("E6",out)
    assert result["cells"]==600
    df.loc[0,"matches_expectation"]=False
    df.to_parquet(out/"results.parquet")
    with pytest.raises(EvidenceAuditError,match="E6:"):
        audit_one("E6",out)
