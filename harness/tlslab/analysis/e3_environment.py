"""Read-only E3 CPU/thermal-snapshot coverage and normalized block-drift diagnostic.

Snapshots are collected before and after each JMH run, not continuously during
the fork. Their variation and correlations cannot prove thermal stability,
throttling, causal effects or clock-control compliance. No results/manifest
mutation, no validation-promotion side effects.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

from .e3_contrasts import _checked_data


def _finite(value):
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if np.isfinite(v) else None


def sensor_statistics(records: list[dict], field: str) -> list[dict]:
    """Aggregate readings by exact sensor ID; never equate sensors by index."""
    samples = defaultdict(list)
    paired = defaultdict(list)
    for index, record in enumerate(records):
        before = record.get("cpu_before", {}).get(field, {}) or {}
        after = record.get("cpu_after", {}).get(field, {}) or {}
        for phase, mapping in (("before", before), ("after", after)):
            if not isinstance(mapping, dict):
                continue
            for sensor, value in mapping.items():
                v = _finite(value)
                if v is not None:
                    samples[str(sensor)].append((index, phase, v))
        if not isinstance(before, dict) or not isinstance(after, dict):
            continue
        for sensor in set(before) & set(after):
            b, a = _finite(before[sensor]), _finite(after[sensor])
            if b is not None and a is not None:
                paired[str(sensor)].append((index, b, a))
    result = []
    for sensor, values in sorted(samples.items()):
        arr = np.array([x[2] for x in values], dtype=float)
        matching = paired.get(sensor, [])
        changes = np.array([a - b for _, b, a in matching], dtype=float)
        starts = np.array([b for _, b, _ in matching], dtype=float)
        ends = np.array([a for _, _, a in matching], dtype=float)
        result.append({
            "sensor": sensor,
            "readings": len(arr),
            "pairs": len(matching),
            "min": float(arr.min()),
            "max": float(arr.max()),
            "median": float(np.median(arr)),
            "median_before": float(np.median(starts)) if len(starts) else None,
            "median_after": float(np.median(ends)) if len(ends) else None,
            "median_after_minus_before": float(np.median(changes)) if len(changes) else None,
            "max_abs_pair_change": float(np.max(np.abs(changes))) if len(changes) else None,
        })
    return result


def normalize_block_throughput(frame: pd.DataFrame) -> list[dict]:
    """Normalize each condition to its own median; aggregate per block.

    This shows possible block-to-block drift without letting differences
    between cipher suites, providers or payload sizes dominate the result.
    """
    keys = ["platform", "suite", "size"]
    f = frame.copy()
    reference = f.groupby(keys)["mib_per_second"].transform("median")
    if reference.isna().any() or (reference <= 0).any():
        raise ValueError("Cannot normalize missing/invalid reference throughput")
    f["relative_to_condition_median"] = f["mib_per_second"] / reference
    result = []
    for block, items in f.groupby("block"):
        vals = items["relative_to_condition_median"].to_numpy(dtype=float)
        result.append({
            "block": int(block),
            "n_conditions": len(items),
            "median_relative_throughput": float(np.median(vals)),
            "min_relative_throughput": float(np.min(vals)),
            "max_relative_throughput": float(np.max(vals)),
            "q05_relative_throughput": float(np.quantile(vals, .05)),
            "q95_relative_throughput": float(np.quantile(vals, .95)),
        })
    return sorted(result, key=lambda x: x["block"])


def diagnose(frame: pd.DataFrame, evidence: list[dict], manifest: dict) -> dict:
    if len(frame) != 360 or len(evidence) != 360:
        raise ValueError("Requires 360 measured rows and 360 per-cell evidence entries")
    indices = [record.get("cell") for record in evidence]
    if indices != list(range(360)):
        raise ValueError("Evidence must be sequential, exact 0..359 cell indices")
    statuses = Counter(x.get("status") for x in evidence)
    if statuses != {"MEASURED": 360}:
        raise ValueError(f"Evidence must be all measured, got {statuses}")
    freqs = sensor_statistics(evidence, "freq_mhz")
    temps = sensor_statistics(evidence, "thermal_c")
    groups = normalize_block_throughput(frame)
    block_x = [b["block"] for b in groups]
    block_y = [b["median_relative_throughput"] for b in groups]
    correlation = stats.spearmanr(block_x, block_y)
    controls = manifest.get("hardware", {}).get("cpu_controls", {})
    per_cell = Counter()
    for row in evidence:
        for name in ("freq_mhz", "thermal_c"):
            for phase in ("cpu_before", "cpu_after"):
                if row.get(phase, {}).get(name):
                    per_cell[name+"_"+phase.removeprefix("cpu_")] += 1
    return {
        "experiment": "E3",
        "source": "original JMH run-specific evidence, not synthetic measurements",
        "records": len(evidence),
        "manifest_disposition": manifest.get("disposition"),
        "jdk": manifest.get("java"),
        "cpu_controls_recorded_at_start": controls,
        "snapshot_presence": dict(per_cell),
        "cpu_frequency_mhz": freqs,
        "temperatures_c": temps,
        "block_relative_throughput": groups,
        "block_throughput_spearman_rho": float(correlation.statistic),
        "block_throughput_spearman_p_exploratory": float(correlation.pvalue),
        "publication_ready": False,
        "caveats": [
            "Snapshot times bracket each JMH run: not continuous sampling or evidence of no throttling",
            "Sensor names are device labels, not all temperature readings represent CPU package",
            "Observed frequency changes may be scheduling, DVFS or sensor-sampling effects",
            "Block-normalized throughput drift cannot establish causal thermal or clock effects",
            "Host CPU controls and measured CPU ns/byte remain unvalidated",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    parser.add_argument("--out", type=Path, help="Default RUN/e3_environment.json")
    ns = parser.parse_args()
    run = ns.run
    frame = _checked_data(run)
    evidence_path = run/"evidence.jsonl"
    evidence = [json.loads(line) for line in evidence_path.read_text().splitlines()
                if line.strip()]
    manifest = json.loads((run/"manifest.json").read_text())
    report = diagnose(frame, evidence, manifest)
    output = ns.out or run/"e3_environment.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print("E3 environment diagnostics — exploratory, read-only")
    print("Run:", run)
    print("JDK:", report["jdk"])
    print("Snapshot presence:", report["snapshot_presence"])
    print("Frequency sensors:", len(report["cpu_frequency_mhz"]))
    print("Temperature sensors:", len(report["temperatures_c"]))
    if report["temperatures_c"]:
        print("\nTemperature readings (°C), by sensor:")
        t = pd.DataFrame(report["temperatures_c"])
        print(t[["sensor", "pairs", "min", "max", "max_abs_pair_change"]]
              .round(2).to_string(index=False))
    print("\nWithin-condition normalized throughput per block:")
    b = pd.DataFrame(report["block_relative_throughput"])
    print(b[["block", "n_conditions", "median_relative_throughput"]]
          .round(4).to_string(index=False))
    print("Exploratory block-order Spearman rho:",
          round(report["block_throughput_spearman_rho"], 4))
    print("Full JSON report:", output)
    print("Publication-ready: false — snapshots cannot establish thermal stability")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
