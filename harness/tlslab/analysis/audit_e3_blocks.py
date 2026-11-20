"""Audit for the new randomized-block JMH design; never edits experimental evidence."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from ..experiment_matrix import plan, e3_conditions
from ..run_e3 import AEAD, ABLATIONS
from .audit_e3 import DIMENSIONS, _result


def audit_blocks(run: Path, manifest: dict, frame: pd.DataFrame) -> dict:
    run = Path(run)
    checks: list[dict] = []
    errors: list[str] = []
    expected = {(x["platform"], x["suite"], int(x["size"])) for x in e3_conditions()}
    if not set((*DIMENSIONS, "block", "position", "fork", "jmh_fork",
                "ops_per_second", "mib_per_second", "wall_ns_per_byte",
                "score_unit", "status", "validated")) <= set(frame.columns):
        return {"run": str(run), "manifest_disposition": manifest.get("disposition"),
                "checks": [], "raw_jmh_errors": ["Required randomized-design columns missing"],
                "coverage_complete": False, "jmh_reconciled": False,
                "structural_audit_passed": False, "publication_ready": False}
    numeric_ok = True
    for _, row in frame.iterrows():
        try:
            ops, mib, wall = (float(row[k]) for k in
                              ("ops_per_second", "mib_per_second", "wall_ns_per_byte"))
            size = int(row["size"])
            if (not np.isfinite([ops, mib, wall]).all() or min(ops, mib, wall) <= 0
                    or row["score_unit"] != "ops/s"
                    or not np.isclose(mib, ops * size / 1048576, rtol=1e-9)
                    or not np.isclose(wall, 1e9 / (ops * size), rtol=1e-9)):
                numeric_ok = False
        except (ValueError, TypeError, KeyError):
            numeric_ok = False
    _result(run, "finite_positive_jmh_scores_and_units", numeric_ok,
            "Observed ops/s reconciled to throughput and wall ns/byte", checks)
    schedule = plan("E3", blocks=10)
    intended = {
        (x["block"], x["position"]): (x["platform"], x["suite"], x["size"])
        for x in schedule
    }
    observed = {}
    for _, row in frame.iterrows():
        try:
            key = (int(row["block"]), int(row["position"]))
            if key in observed:
                errors.append(f"Duplicate block/position {key}")
            observed[key] = (str(row["platform"]), str(row["suite"]), int(row["size"]))
        except (ValueError, TypeError):
            errors.append("Non-integer block/position/size")
    order_ok = observed == intended
    all_measured = frame["status"].eq("MEASURED").all() and len(frame) == 360
    _result(run, "randomized_cross_condition_blocks", order_ok and all_measured,
            "10 blocks x 36 seeded-shuffled conditions, one per block position", checks)
    grouped = frame.groupby(list(DIMENSIONS), dropna=False)
    forks_ok = len(grouped) == 36 and all(
        len(g) == 10 and set(g["block"].astype(int)) == set(range(1, 11))
        and (g["fork"].astype(int) == g["block"].astype(int)).all()
        and g["jmh_fork"].eq(1).all()
        for _, g in grouped
    )
    _result(run, "distinct_jmh_forks", forks_ok,
            "Every condition has one independent JMH fork in each of 10 blocks", checks)
    coverage = all_measured and forks_ok and order_ok
    _result(run, "complete_factor_matrix", coverage,
            f"{len(frame)} rows; {len(grouped)} conditions; exact frozen block schedule", checks)

    raw_files = sorted((run/"jmh").glob("*.json"))
    evidence_file = run/"evidence.jsonl"
    try:
        evidence = [json.loads(x) for x in evidence_file.read_text().splitlines() if x]
    except (OSError, ValueError) as exc:
        evidence = []
        errors.append(f"evidence.jsonl: {type(exc).__name__}: {exc}")
    env_path = run/"environment.jsonl"
    try:
        env = [json.loads(x) for x in env_path.read_text().splitlines() if x]
    except (OSError, ValueError) as exc:
        env = []
        errors.append(f"environment.jsonl: {type(exc).__name__}: {exc}")

    reconciled = 0
    seen = set()
    for rec in evidence:
        try:
            index = int(rec["cell"])
            if index in seen or not 0 <= index < 360:
                raise ValueError("Duplicate or invalid indexed JMH cell")
            seen.add(index)
            scheduled = schedule[index]
            for field in ("block", "position"):
                if int(rec[field]) != scheduled[field]:
                    raise ValueError("Evidence block/order disagrees with frozen schedule")
            file = run/"jmh"/f"{index:04d}.json"
            if Path(rec["file"]).name != file.name:
                raise ValueError("Evidence references wrong JMH result file")
            if rec["status"] != "MEASURED" or int(rec["forks"]) != 1:
                raise ValueError("JMH evidence not a single successful fork")
            entries = json.loads(file.read_text())
            if len(entries) != 1:
                raise ValueError("Expected exactly one JMH result")
            entry = entries[0]
            params = entry["params"]
            condition = (
                scheduled["platform"], scheduled["suite"], scheduled["size"]
            )
            expected_provider = "BC" if condition[0] == "BC" else "SunJCE"
            if (params["provider"] != expected_provider
                or params["aead"] != AEAD[condition[1]]
                or int(params["size"]) != condition[2]
                or rec["flags"] != ABLATIONS.get(condition[0], [])):
                raise ValueError("JMH parameters or JVM flags disagree with experimental cell")
            metric = entry["primaryMetric"]
            raw = metric["rawData"]
            if metric["scoreUnit"] != "ops/s" or len(raw) != 1 or not raw[0]:
                raise ValueError("Invalid JMH raw fork")
            match = frame[
                (frame["block"] == scheduled["block"])
                & (frame["position"] == scheduled["position"])
            ]
            if len(match) != 1:
                raise ValueError("Missing or ambiguous Parquet row for JMH file")
            expected_ops = float(np.mean(raw[0]))
            if not np.isclose(float(match.iloc[0]["ops_per_second"]),
                              expected_ops, rtol=1e-9, atol=1e-9):
                raise ValueError("JMH fork rawData differs from stored Parquet score")
            reconciled += 1
        except (OSError, ValueError, TypeError, KeyError, IndexError) as exc:
            errors.append(f"cell {rec.get('cell', '?')}: {type(exc).__name__}: {exc}")
    provenance_ok = (len(raw_files) == len(evidence) == len(seen) == reconciled == 360
                     and not errors)
    _result(run, "raw_jmh_provenance", provenance_ok,
            f"{len(raw_files)} raw JSON files, {len(evidence)} evidence entries, "
            f"{reconciled}/360 verified fork means", checks)
    snapshots = bool(env and env[0].get("phase") == "start"
                     and env[-1].get("phase") == "end"
                     and all("cpu_before" in rec and "cpu_after" in rec
                             for rec in evidence))
    _result(run, "environment_snapshots_recorded", snapshots,
            "CPU clocks/sensor observations recorded; availability and stability not yet asserted", checks)
    # new_run captures host settings *before* optional tuning. Compare the
    # observations inside the tuned context rather than the pre-run manifest.
    before_controls = (env[0].get("cpu", {}).get("cpu_controls", {})
                       if env else {})
    after_controls = (env[-1].get("cpu", {}).get("cpu_controls", {})
                      if env else {})
    governor_ok = all(
        bool(c.get("governors"))
        and all(v == "performance" for v in c.get("governors", {}).values())
        and c.get("intel_no_turbo") == "1"
        for c in (before_controls, after_controls)
    )
    _result(run, "documented_cpu_controls", governor_ok,
            "Tuned-context start and end snapshots must both show performance governor and disabled turbo", checks)
    sensor_count = sum(bool(x.get("cpu_before", {}).get("thermal_c"))
                       for x in evidence)
    clock_count = sum(bool(x.get("cpu_before", {}).get("freq_mhz"))
                      for x in evidence)
    _result(run, "cpu_clock_thermal_samples", clock_count == 360 and sensor_count == 360,
            f"Frequency available for {clock_count}/360 and temperature for {sensor_count}/360 cells; sensor availability is not proof of stability", checks)
    _result(run, "measured_cpu_ns_per_byte",
            "cpu_ns_per_byte" in frame and frame["cpu_ns_per_byte"].notna().all(),
            "CPU time/byte cannot be replaced with wall time/byte", checks)
    windows = [x.get("thermal") for x in evidence if x.get("status") == "MEASURED"]
    stable = (len(windows) == 360 and all(
        w and w.get("ok") and w.get("throttle_events") == 0 and w.get("throttle_counters", 0) > 0
        for w in windows))
    _result(run, "independent_thermal_stability", stable,
            "Every cell needs a met cool-down gate and zero kernel thermal-throttle events "
            "(thermal_throttle counters); temperature snapshots alone are not accepted", checks)
    critical = {
        "finite_positive_jmh_scores_and_units", "randomized_cross_condition_blocks",
        "distinct_jmh_forks", "complete_factor_matrix", "raw_jmh_provenance",
    }
    return {
        "run": str(run),
        "manifest_disposition": manifest.get("disposition"),
        "checks": checks,
        "raw_jmh_errors": errors[:40],
        "coverage_complete": coverage,
        "jmh_reconciled": provenance_ok,
        "structural_audit_passed": all(x["passed"] for x in checks if x["check"] in critical),
        "publication_ready": False,
        "note": "Read-only audit of 10 randomized blocks; no validated flags mutated.",
    }
