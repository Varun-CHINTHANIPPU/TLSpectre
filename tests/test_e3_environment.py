"""Read-only E3 environmental diagnostics preserve sensor labels and block pairing."""
import copy

import pandas as pd
import pytest

from tlslab.analysis.e3_environment import diagnose, sensor_statistics, normalize_block_throughput
from tlslab.experiment_matrix import plan


def _fake_run():
    records = []
    rows = []
    for i, condition in enumerate(plan("E3", blocks=10)):
        block = condition["block"]
        size = condition["size"]
        factor = {"SunJCE": 1.0, "BC": .5, "A4": .2, "A5": .7}[condition["platform"]]
        rows.append({**condition, "status": "MEASURED",
                     "mib_per_second": factor * size * (1.0 + block / 100)})
        records.append({
            "cell": i, "status": "MEASURED",
            "cpu_before": {
                "freq_mhz": {"cpu0": 3100.0 + block},
                "thermal_c": {"coretemp:temp1_input": 55 + block,
                              "nvme:temp1_input": 45.0},
            },
            "cpu_after": {
                "freq_mhz": {"cpu0": 3150.0 + block},
                "thermal_c": {"coretemp:temp1_input": 57 + block,
                              "nvme:temp1_input": 45.0},
            },
        })
    manifest = {"experiment": "E3", "disposition": "PARTIAL",
                "java": "openjdk 21", "hardware": {
                    "cpu_controls": {"intel_no_turbo": "0",
                                     "governors": {"cpu0": "powersave"}}
                }}
    return pd.DataFrame(rows), records, manifest


def test_sensor_statistics_preserve_distinct_sensor_identity():
    frame, records, manifest = _fake_run()
    data = sensor_statistics(records, "thermal_c")
    assert {s["sensor"] for s in data} == {
        "coretemp:temp1_input", "nvme:temp1_input"}
    by_name = {x["sensor"]: x for x in data}
    assert by_name["coretemp:temp1_input"]["pairs"] == 360
    assert by_name["coretemp:temp1_input"]["max_abs_pair_change"] == 2
    assert by_name["nvme:temp1_input"]["max_abs_pair_change"] == 0


def test_diagnose_reports_actual_sensors_and_normalized_block_drift():
    frame, records, manifest = _fake_run()
    report = diagnose(frame, records, manifest)
    assert report["records"] == 360
    assert len(report["cpu_frequency_mhz"]) == 1
    assert len(report["temperatures_c"]) == 2
    assert report["snapshot_presence"]["freq_mhz_before"] == 360
    assert report["snapshot_presence"]["thermal_c_after"] == 360
    assert len(report["block_relative_throughput"]) == 10
    assert all(x["n_conditions"] == 36 for x in report["block_relative_throughput"])
    assert report["block_throughput_spearman_rho"] > .99
    assert report["publication_ready"] is False


def test_diagnose_fails_closed_with_missing_cell_or_failed_evidence():
    frame, records, manifest = _fake_run()
    with pytest.raises(ValueError, match="360"):
        diagnose(frame, records[:-1], manifest)
    altered = copy.deepcopy(records)
    altered[22]["cell"] = 23
    with pytest.raises(ValueError, match="sequential"):
        diagnose(frame, altered, manifest)
    altered = copy.deepcopy(records)
    altered[22]["status"] = "FAILED"
    with pytest.raises(ValueError, match="all measured"):
        diagnose(frame, altered, manifest)


def test_normalization_does_not_pool_raw_throughput_across_cipher_conditions():
    frame, _, _ = _fake_run()
    blocks = normalize_block_throughput(frame)
    assert blocks[-1]["median_relative_throughput"] > blocks[0]["median_relative_throughput"]
    assert blocks[0]["median_relative_throughput"] > 0
