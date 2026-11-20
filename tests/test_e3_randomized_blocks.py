"""Prove that E3 block order and per-fork evidence are independently checked."""
import json

import pandas as pd

from tlslab.analysis.audit_e3 import audit
from tlslab.experiment_matrix import plan
from tlslab.run_e3 import AEAD, ABLATIONS, selected_schedule


def _new_dataset(root):
    (root / "jmh").mkdir()
    (root / "manifest.json").write_text(json.dumps({
        "experiment": "E3", "disposition": "PARTIAL",
        "metadata": {"pilot": False, "replication_design": "randomized cross-condition blocks"},
        "hardware": {"cpu_controls": {"intel_no_turbo": "0",
                                     "governors": {"cpu0": "powersave"}}},
    }))
    rows, logs = [], []
    for index, cell in enumerate(plan("E3", blocks=10)):
        score = float(100 + index)
        platform = cell["platform"]
        provider = "BC" if platform == "BC" else "SunJCE"
        file = root / "jmh" / f"{index:04d}.json"
        file.write_text(json.dumps([{
            "params": {"aead": AEAD[cell["suite"]], "size": str(cell["size"]),
                       "provider": provider},
            "primaryMetric": {"scoreUnit": "ops/s", "rawData": [[score - 1, score + 1]]},
        }]))
        logs.append({"cell": index, "block": cell["block"], "position": cell["position"],
                     "status": "MEASURED", "forks": 1,
                     "flags": ABLATIONS.get(platform, []), "file": str(file),
                     "cpu_before": {"freq_mhz": {}}, "cpu_after": {"freq_mhz": {}}})
        rows.append({**cell, "fork": cell["block"], "jmh_fork": 1,
                     "ops_per_second": score,
                     "mib_per_second": score * cell["size"] / 1048576,
                     "wall_ns_per_byte": 1e9 / (score * cell["size"]),
                     "cpu_ns_per_byte": None, "score_unit": "ops/s",
                     "status": "MEASURED", "validated": False})
    (root / "evidence.jsonl").write_text(
        "\n".join(json.dumps(e) for e in logs) + "\n"
    )
    (root / "environment.jsonl").write_text(
        json.dumps({"phase": "start"}) + "\n"
        + json.dumps({"phase": "end"}) + "\n"
    )
    pd.DataFrame(rows).to_parquet(root / "results.parquet")


def _check(report, field):
    return next(r["passed"] for r in report["checks"] if r["check"] == field)


def test_seeded_block_schedule_is_complete_and_reproducible():
    schedule = selected_schedule(pilot=False)
    assert schedule == plan("E3", blocks=10)
    assert len(schedule) == 360
    assert len(selected_schedule(pilot=True)) == 2
    assert {x["platform"] for x in selected_schedule(pilot=True)} == {"SunJCE", "A5"}
    assert len({
        (item["block"], item["position"]) for item in schedule
    }) == 360
    for block in range(1, 11):
        rows = [r for r in schedule if r["block"] == block]
        assert len(rows) == 36
        assert set(r["position"] for r in rows) == set(range(36))
        assert len({(r["suite"], r["size"], r["platform"]) for r in rows}) == 36


def test_full_block_design_reconciles_but_stays_scientifically_partial(tmp_path):
    _new_dataset(tmp_path)
    result = audit(tmp_path)
    assert result["coverage_complete"]
    assert result["jmh_reconciled"]
    assert result["structural_audit_passed"]
    assert _check(result, "randomized_cross_condition_blocks")
    assert _check(result, "environment_snapshots_recorded")
    assert not _check(result, "documented_cpu_controls")
    assert not result["publication_ready"]


def test_block_audit_rejects_out_of_order_cell(tmp_path):
    _new_dataset(tmp_path)
    frame = pd.read_parquet(tmp_path / "results.parquet")
    frame.loc[0, "position"] = 35
    frame.to_parquet(tmp_path / "results.parquet")
    result = audit(tmp_path)
    assert not _check(result, "randomized_cross_condition_blocks")
    assert not result["structural_audit_passed"]


def test_block_audit_rejects_tampered_jmh_fork_mean(tmp_path):
    _new_dataset(tmp_path)
    frame = pd.read_parquet(tmp_path / "results.parquet")
    frame.loc[0, "ops_per_second"] += 10
    frame.to_parquet(tmp_path / "results.parquet")
    result = audit(tmp_path)
    assert not result["jmh_reconciled"]
    assert not result["structural_audit_passed"]


def test_block_audit_rejects_missing_raw_jmh_file(tmp_path):
    _new_dataset(tmp_path)
    (tmp_path / "jmh" / "0000.json").unlink()
    result = audit(tmp_path)
    assert not result["jmh_reconciled"]
    assert not result["structural_audit_passed"]
