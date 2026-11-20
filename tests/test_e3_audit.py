"""E3 raw evidence must reconcile before numerical measurements can be trusted."""
import json

import pandas as pd

from tlslab.analysis.audit_e3 import audit
from tlslab.experiment_matrix import e3_conditions
from tlslab.run_e3 import AEAD, ABLATIONS


def _dataset(root):
    jmh = root / "jmh"
    jmh.mkdir()
    (root / "manifest.json").write_text(json.dumps({
        "experiment": "E3",
        "disposition": "PARTIAL",
        "metadata": {"pilot": False},
        "hardware": {"cpu_controls": {
            "intel_no_turbo": "0", "governors": {"cpu0": "powersave"}
        }},
    }))
    rows = []
    evidence = []
    for index, cell in enumerate(e3_conditions()):
        platform = cell["platform"]
        provider = "BC" if platform == "BC" else "SunJCE"
        flags = ABLATIONS.get(platform, [])
        values = [[100.0 + index + fork, 102.0 + index + fork]
                  for fork in range(10)]
        (jmh / f"{index:02d}.json").write_text(json.dumps([{
            "params": {
                "aead": AEAD[cell["suite"]],
                "size": str(cell["size"]),
                "provider": provider,
            },
            "primaryMetric": {"scoreUnit": "ops/s", "rawData": values},
        }]))
        evidence.append({"cell": index, "status": "MEASURED", "forks": 10,
                         "flags": flags, "file": str(jmh / f"{index:02d}.json")})
        for fork, sample in enumerate(values, 1):
            score = sum(sample) / len(sample)
            rows.append({
                **cell,
                "experiment": "E3", "block": 1, "position": index,
                "fork": fork, "ops_per_second": score,
                "mib_per_second": score * cell["size"] / 1048576,
                "wall_ns_per_byte": 1e9 / (score * cell["size"]),
                "cpu_ns_per_byte": None, "score_unit": "ops/s",
                "status": "MEASURED", "validated": False,
            })
    (root / "evidence.jsonl").write_text(
        "\n".join(json.dumps(x) for x in evidence) + "\n"
    )
    pd.DataFrame(rows).to_parquet(root / "results.parquet")
    return pd.DataFrame(rows)


def _check(report, name):
    return next(x["passed"] for x in report["checks"] if x["check"] == name)


def test_e3_existing_fork_design_structurally_audits_but_cannot_claim_blocks(tmp_path):
    _dataset(tmp_path)
    report = audit(tmp_path)
    assert report["coverage_complete"]
    assert report["jmh_reconciled"]
    assert report["structural_audit_passed"]
    assert not report["publication_ready"]
    assert not _check(report, "randomized_cross_condition_blocks")
    assert not _check(report, "measured_cpu_ns_per_byte")
    assert not _check(report, "documented_cpu_controls")


def test_e3_audit_rejects_tampered_fork_mean(tmp_path):
    df = _dataset(tmp_path)
    df.loc[0, "ops_per_second"] += 20
    df.to_parquet(tmp_path / "results.parquet")
    report = audit(tmp_path)
    assert not report["jmh_reconciled"]
    assert not report["structural_audit_passed"]
    assert any("does not reconcile" in e for e in report["raw_jmh_errors"])


def test_e3_audit_rejects_missing_raw_file(tmp_path):
    _dataset(tmp_path)
    (tmp_path / "jmh" / "00.json").unlink()
    report = audit(tmp_path)
    assert not report["structural_audit_passed"]
    assert not report["jmh_reconciled"]


def test_e3_audit_rejects_incomplete_fork_set(tmp_path):
    df = _dataset(tmp_path)
    df = df.drop(index=0)
    df.to_parquet(tmp_path / "results.parquet")
    report = audit(tmp_path)
    assert not report["coverage_complete"]
    assert not _check(report, "distinct_jmh_forks")
    assert not report["structural_audit_passed"]
