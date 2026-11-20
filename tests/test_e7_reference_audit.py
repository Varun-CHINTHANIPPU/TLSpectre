"""E7 reference audit: strict factor coverage, validation and non-paired inference."""
import json
from pathlib import Path

import pandas as pd
import pytest

from tlslab.analysis.audit_e7_reference import audit, ReferenceEvidenceError
from tlslab.analysis.artifacts import artifact_figure, InsufficientEvidence
from tlslab.experiment_matrix import plan


def fixture(tmp_path):
    a = tmp_path/"data/raw/E7/a"
    b = tmp_path/"data/references/E7/b"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    rows = []
    for item in plan("E7"):
        rows.append({
            **item, "status": "MEASURED", "validated": True,
            "handshake_ms": 1.2 + 0.01*item["block"],
            "n_handshakes": 1 if item["stapling"] == "cold" else 500,
            "staple_state_verified": True, "full_handshake_verified": True,
            "thermal_ok": True,
            "thermal_window_scope":
                "timed client batch + same-process untimed client warm-up",
        })
    pd.DataFrame(rows).to_parquet(a/"results.parquet")
    pd.DataFrame([{**x, "stack": "nginx/OpenSSL B3",
                   "handshake_ms": x["handshake_ms"]*1.05} for x in rows]).to_parquet(b/"results.parquet")
    for folder, reference in ((a, False), (b, True)):
        (folder/"manifest.json").write_text(json.dumps({
            "experiment": "E7", "disposition": "COMPLETE" if reference else "PARTIAL",
            "metadata": {"pilot": False, "isolated": True,
                         "reference_only": reference},
            "hardware": {"cpu_model": "synthetic unit fixture", "cpu_count": 16},
            "java": "JDK 27", "openssl": "OpenSSL 3", "nginx": "nginx 1",
            "details": {"cpu_tuning": {
                "requested": False, "tuned": False,
                "effective_controls": {"governors": {"cpu0": "performance"},
                                       "intel_no_turbo": "1"}}}
        }))
    return a, b


def test_audit_accepts_complete_distinct_reference_without_claiming_paired_inference(tmp_path):
    a,b = fixture(tmp_path)
    result = audit(a,b)
    assert len(result) == 6
    assert result["main_n"].eq(30).all()
    assert result["reference_n"].eq(30).all()
    assert result["reference_over_main_ratio"].round(2).eq(1.05).all()
    assert "unpaired" in result["comparison_scope"].iloc[0]
    # Only now may the E7 F6 figure be generated, using independently
    # validated reference data to remove the primary PARTIAL gate.
    figure = artifact_figure("F6", root=tmp_path)
    assert figure.is_file()


def test_partial_reference_cannot_validate_primary_e7(tmp_path):
    a,b=fixture(tmp_path)
    manifest=b/"manifest.json"
    data=json.loads(manifest.read_text())
    data["disposition"]="PARTIAL"
    manifest.write_text(json.dumps(data))
    with pytest.raises(ReferenceEvidenceError, match="not COMPLETE"):
        audit(a,b)
    with pytest.raises(InsufficientEvidence, match="reference"):
        artifact_figure("F6", root=tmp_path)


def test_duplicate_or_missing_reference_factor_rejected(tmp_path):
    a,b=fixture(tmp_path)
    df=pd.read_parquet(b/"results.parquet")
    df.loc[0, ["block","stapling","rtt_ms"]]=df.loc[1, ["block","stapling","rtt_ms"]]
    df.to_parquet(b/"results.parquet")
    with pytest.raises(ReferenceEvidenceError, match="factor"):
        audit(a,b)


def test_bad_reference_staple_or_wrong_host_is_not_valid(tmp_path):
    a,b=fixture(tmp_path)
    df=pd.read_parquet(b/"results.parquet")
    df.loc[0,"staple_state_verified"]=False
    df.to_parquet(b/"results.parquet")
    with pytest.raises(ReferenceEvidenceError, match="not validated"):
        audit(a,b)
    df.loc[0,"staple_state_verified"]=True
    df.to_parquet(b/"results.parquet")
    manifest=b/"manifest.json"
    data=json.loads(manifest.read_text())
    data["hardware"]["cpu_model"]="different CPU"
    manifest.write_text(json.dumps(data))
    with pytest.raises(ReferenceEvidenceError, match="host"):
        audit(a,b)


def test_nonisolated_reference_is_excluded(tmp_path):
    a,b=fixture(tmp_path)
    m=b/"manifest.json"
    d=json.loads(m.read_text())
    d["metadata"]["isolated"]=False
    m.write_text(json.dumps(d))
    with pytest.raises(ReferenceEvidenceError, match="non-isolated"):
        audit(a,b)


def test_legacy_broad_thermal_window_is_not_comparable(tmp_path):
    a,b=fixture(tmp_path)
    legacy=pd.read_parquet(a/"results.parquet")
    legacy=legacy.drop(columns=["thermal_window_scope"])
    legacy.to_parquet(a/"results.parquet")
    with pytest.raises(ReferenceEvidenceError, match="missing evidence columns"):
        audit(a,b)


def test_changed_thermal_window_semantics_cannot_be_paired(tmp_path):
    a,b=fixture(tmp_path)
    legacy=pd.read_parquet(a/"results.parquet")
    legacy["thermal_window_scope"]="entire setup warmup measurement and verification"
    legacy.to_parquet(a/"results.parquet")
    with pytest.raises(ReferenceEvidenceError, match="thermal window scope mismatch"):
        audit(a,b)


def test_cpu_tuning_mismatch_blocks_e7_cross_run_inference(tmp_path):
    a,b=fixture(tmp_path)
    manifest=b/"manifest.json"
    doc=json.loads(manifest.read_text())
    doc["details"]["cpu_tuning"]["effective_controls"]["intel_no_turbo"]="0"
    manifest.write_text(json.dumps(doc))
    with pytest.raises(ReferenceEvidenceError, match="CPU governor/turbo"):
        audit(a,b)


def test_missing_cpu_tuning_evidence_is_rejected(tmp_path):
    a,b=fixture(tmp_path)
    manifest=a/"manifest.json"
    doc=json.loads(manifest.read_text())
    del doc["details"]["cpu_tuning"]
    manifest.write_text(json.dumps(doc))
    with pytest.raises(ReferenceEvidenceError, match="CPU governor/turbo"):
        audit(a,b)
