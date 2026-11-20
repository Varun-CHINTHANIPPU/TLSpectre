"""Exploratory E3 inference tests use block pairing and never certify raw evidence."""
import json

import numpy as np
import pandas as pd
import pytest

from tlslab.analysis.e3_contrasts import contrast_table, _checked_data
from tlslab.experiment_matrix import SUITES


def _full_frame():
    rows = []
    for block in range(1, 11):
        for suite in SUITES:
            for size in (64, 1024, 16384):
                baseline = 100 + block
                for platform in ("SunJCE", "BC", "A4", "A5"):
                    factor = {"SunJCE": 1.0, "BC": .5,
                              "A4": .2, "A5": .7}[platform]
                    if (suite == "TLS_CHACHA20_POLY1305_SHA256"
                            and size == 64 and platform == "A5"):
                        factor = 1.1 if block % 2 == 0 else .9
                    rows.append({
                        "block": block, "suite": suite, "size": size,
                        "platform": platform, "mib_per_second": baseline * factor,
                        "status": "MEASURED",
                    })
    return pd.DataFrame(rows)


def _run(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({
        "experiment": "E3", "disposition": "PARTIAL",
        "metadata": {"pilot": False,
                     "replication_design": "randomized cross-condition blocks"},
    }))
    (tmp_path / "audit.json").write_text(json.dumps({
        "run": str(tmp_path), "structural_audit_passed": True,
        "coverage_complete": True, "jmh_reconciled": True,
        "publication_ready": False,
    }))
    _full_frame().to_parquet(tmp_path / "results.parquet")
    return tmp_path


def test_e3_contrasts_preserve_block_pairing_and_adjust_all_18_tests():
    report = contrast_table(_full_frame(), bootstrap_samples=1000, seed=7)
    assert len(report) == 18
    assert report["n_blocks"].eq(10).all()
    aes = report[(report["suite"] == "TLS_AES_128_GCM_SHA256")
                 & (report["size"] == 16384)
                 & (report["comparison"] == "A4/SunJCE")].iloc[0]
    assert aes["median_ratio"] == pytest.approx(.2)
    assert aes["ci_low_percentile"] == pytest.approx(.2)
    assert aes["ci_high_percentile"] == pytest.approx(.2)
    assert aes["n_below_1"] == 10
    assert aes["p_sign_exact"] == pytest.approx(2 / (2 ** 10))
    assert aes["p_holm_18"] == pytest.approx(18 * 2 / (2 ** 10))
    mixed = report[(report["suite"] == "TLS_CHACHA20_POLY1305_SHA256")
                   & (report["size"] == 64)
                   & (report["comparison"] == "A5/SunJCE")].iloc[0]
    assert mixed["n_above_1"] == 5
    assert mixed["n_below_1"] == 5
    assert mixed["p_sign_exact"] == 1.0
    assert np.isfinite(report["ci_low_percentile"]).all()
    assert np.isfinite(report["ci_high_percentile"]).all()


def test_e3_requires_existing_passed_matching_audit(tmp_path):
    run = _run(tmp_path)
    assert len(_checked_data(run)) == 360
    (run / "audit.json").unlink()
    with pytest.raises(ValueError, match="audit"):
        _checked_data(run)
    (run / "audit.json").write_text(json.dumps({
        "run": str(run), "coverage_complete": True,
        "jmh_reconciled": False, "structural_audit_passed": True,
    }))
    with pytest.raises(ValueError, match="audit"):
        _checked_data(run)


def test_e3_rejects_missing_or_duplicate_block_condition(tmp_path):
    run = _run(tmp_path)
    frame = pd.read_parquet(run / "results.parquet")
    frame.iloc[:-1].to_parquet(run / "results.parquet")
    with pytest.raises(ValueError, match="360"):
        _checked_data(run)
    duplicate = pd.concat([frame.iloc[:-1], frame.iloc[[0]]], ignore_index=True)
    duplicate.to_parquet(run / "results.parquet")
    with pytest.raises(ValueError, match="Duplicate"):
        _checked_data(run)


def test_e3_rejects_pilot_or_old_nonrandomized_run(tmp_path):
    run = _run(tmp_path)
    manifest = json.loads((run / "manifest.json").read_text())
    manifest["metadata"]["pilot"] = True
    (run / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="full E3"):
        _checked_data(run)
