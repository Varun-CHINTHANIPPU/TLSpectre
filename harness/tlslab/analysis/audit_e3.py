"""Read-only provenance and measurement audit of an existing E3 JMH dataset.

The audit never changes validated flags, source Parquet, or run manifests.
It distinguishes complete numerical coverage from randomized block inference,
CPU-time measurement and independently controlled thermal/host conditions.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

import numpy as np
import pandas as pd

from ..experiment_matrix import e3_conditions
from ..run_e3 import AEAD, ABLATIONS


DIMENSIONS = ("platform", "suite", "size")
EXPECTED_FORKS = 10


def _result(run: Path, check: str, ok: bool, detail: str, items: list[dict]):
    items.append({"check": check, "passed": bool(ok), "detail": detail})


def audit(run: Path) -> dict:
    run = Path(run)
    manifest = json.loads((run / "manifest.json").read_text())
    if manifest.get("experiment") != "E3" or manifest.get("metadata", {}).get("pilot"):
        raise ValueError("Expected a full, non-pilot E3 manifest")
    frame = pd.read_parquet(run / "results.parquet")
    if manifest.get("metadata", {}).get("replication_design") == "randomized cross-condition blocks":
        from .audit_e3_blocks import audit_blocks
        return audit_blocks(run, manifest, frame)
    findings: list[dict] = []
    columns = set(DIMENSIONS) | {
        "fork", "ops_per_second", "mib_per_second",
        "wall_ns_per_byte", "score_unit", "status", "validated", "block",
    }
    missing = sorted(columns - set(frame.columns))
    if missing:
        return {"run": str(run), "checks": [], "fatal": [f"Missing columns: {missing}"],
                "coverage_complete": False, "jmh_reconciled": False,
                "publication_ready": False}
    expected = {(c["platform"], c["suite"], int(c["size"])) for c in e3_conditions()}
    actual = {
        (str(p), str(s), int(n))
        for p, s, n in frame[list(DIMENSIONS)].drop_duplicates().itertuples(index=False, name=None)
    }
    _result(run, "complete_factor_matrix",
            actual == expected and len(frame) == 360 and frame["status"].eq("MEASURED").all(),
            f"Observed {len(actual)}/36 conditions and {len(frame)}/360 measured rows", findings)
    keys = frame.groupby(list(DIMENSIONS), dropna=False, sort=False)
    good_forks = all(
        len(group) == EXPECTED_FORKS
        and set(group["fork"].astype(int)) == set(range(1, EXPECTED_FORKS + 1))
        for _, group in keys
    )
    _result(run, "distinct_jmh_forks", good_forks,
            "Expected forks 1..10 once per condition", findings)
    finite_positive = True
    formulas_match = True
    for _, row in frame.iterrows():
        try:
            ops = float(row["ops_per_second"])
            mib = float(row["mib_per_second"])
            wall = float(row["wall_ns_per_byte"])
            size = int(row["size"])
        except (ValueError, TypeError):
            finite_positive = False
            formulas_match = False
            continue
        if not (np.isfinite([ops, mib, wall]).all() and min(ops, mib, wall) > 0
                and row["score_unit"] == "ops/s"):
            finite_positive = False
            continue
        if not (np.isclose(mib, ops * size / 1048576, rtol=1e-9)
                and np.isclose(wall, 1e9 / (ops * size), rtol=1e-9)):
            formulas_match = False
    _result(run, "finite_positive_jmh_scores", finite_positive,
            "ops/s, MiB/s and wall ns/byte must be finite and positive", findings)
    _result(run, "rate_unit_reconciliation", formulas_match,
            "Recomputed throughput and wall-time units from ops/s and payload size", findings)

    provenance_errors = []
    reconciled = 0
    raw_files = sorted((run / "jmh").glob("*.json"))
    matched = set()
    for path in raw_files:
        try:
            entries = json.loads(path.read_text())
            if len(entries) != 1:
                raise ValueError("Expected exactly one JMH result")
            entry = entries[0]
            params = entry["params"]
            suite = next((s for s, aead in AEAD.items() if aead == params["aead"]), None)
            size = int(params["size"])
            provider = params["provider"]
            # Two JVM-ablation conditions use SunJCE but are disambiguated
            # by the recorded command flag list in evidence.jsonl.
            matches = [(p, s, n) for p, s, n in expected
                       if s == suite and n == size
                       and (("BC" if p == "BC" else "SunJCE") == provider)]
            if not matches:
                raise ValueError("Unknown JMH parameter combination")
            if entry["primaryMetric"]["scoreUnit"] != "ops/s":
                raise ValueError("Unexpected JMH metric unit")
            raw = entry["primaryMetric"]["rawData"]
            if len(raw) != EXPECTED_FORKS or any(not values for values in raw):
                raise ValueError("Missing independent JMH fork rawData")
            # File index maps to the exact randomized-plan cell. This is
            # additionally cross-checked against the runner's evidence row.
            if not path.stem.isdigit():
                raise ValueError("JMH file name not a numbered cell")
            matched.add(path.name)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            provenance_errors.append(f"{path.name}: {type(exc).__name__}: {exc}")

    # Reconcile source JMH rawData against the Parquet fork means using
    # evidence.jsonl for the actual cell identity and provider ablation flags.
    evidence_path = run / "evidence.jsonl"
    try:
        evidence = [json.loads(line) for line in evidence_path.read_text().splitlines()]
    except (OSError, ValueError) as exc:
        evidence = []
        provenance_errors.append(f"evidence.jsonl: {type(exc).__name__}: {exc}")
    seen_conditions = set()
    for rec in evidence:
        try:
            file = run / "jmh" / f"{int(rec['cell']):02d}.json"
            entry = json.loads(file.read_text())[0]
            params = entry["params"]
            suite = next(s for s, aead in AEAD.items() if aead == params["aead"])
            size = int(params["size"])
            provider = params["provider"]
            flags = rec["flags"]
            if flags == ABLATIONS["A4"]:
                platform = "A4"
            elif flags == ABLATIONS["A5"]:
                platform = "A5"
            elif not flags:
                platform = "BC" if provider == "BC" else "SunJCE"
            else:
                raise ValueError("Undeclared JVM intrinsics ablation")
            if provider != ("BC" if platform == "BC" else "SunJCE"):
                raise ValueError("Provider does not match recorded JVM flags")
            condition = (platform, suite, size)
            if condition in seen_conditions:
                raise ValueError("Duplicate condition in raw evidence")
            seen_conditions.add(condition)
            records = frame[
                (frame["platform"] == platform)
                & (frame["suite"] == suite)
                & (frame["size"] == size)
            ].set_index("fork")
            raw = entry["primaryMetric"]["rawData"]
            if len(records) != EXPECTED_FORKS or len(raw) != EXPECTED_FORKS:
                raise ValueError("Incorrect per-condition fork count")
            for n, sample in enumerate(raw, start=1):
                if not sample or not np.isclose(
                    float(records.loc[n, "ops_per_second"]),
                    float(np.mean(sample)), rtol=1e-9, atol=1e-9
                ):
                    raise ValueError(f"Fork {n} does not reconcile with raw JMH")
                reconciled += 1
        except (OSError, KeyError, TypeError, ValueError, StopIteration) as exc:
            provenance_errors.append(
                f"cell {rec.get('cell', '?')}: {type(exc).__name__}: {exc}"
            )
    jmh_reconciled = (
        len(raw_files) == 36 and len(evidence) == 36
        and len(seen_conditions) == 36 and reconciled == 360
        and not provenance_errors
    )
    _result(run, "raw_jmh_provenance", jmh_reconciled,
            f"{len(raw_files)} JMH files, {len(evidence)} evidence records, "
            f"{reconciled}/360 fork means reconciled", findings)

    blocks = {int(b) for b in frame["block"].dropna().unique()}
    randomized_blocks = blocks == set(range(1, 11)) and all(
        frame[frame["block"] == block][list(DIMENSIONS)].drop_duplicates().shape[0] == 36
        for block in range(1, 11)
    )
    _result(run, "randomized_cross_condition_blocks", randomized_blocks,
            f"Observed block IDs {sorted(blocks)}; JMH forks do not substitute for randomized cross-condition blocks",
            findings)

    cpu_ns = "cpu_ns_per_byte" in frame and frame["cpu_ns_per_byte"].notna().all()
    _result(run, "measured_cpu_ns_per_byte", cpu_ns,
            "CPU time per byte is a separate metric and must not be inferred from wall time", findings)
    governors = manifest.get("hardware", {}).get("cpu_controls", {})
    _result(run, "documented_cpu_controls",
            bool(governors.get("governors")) and governors.get("intel_no_turbo") == "1"
            and all(g == "performance" for g in governors.get("governors", {}).values()),
            "Performance governor and disabled turbo not both recorded at capture time", findings)
    _result(run, "independent_thermal_stability",
            bool(manifest.get("metadata", {}).get("thermal_stability_evidence")),
            "No independent run-specific temperature/frequency stability evidence", findings)
    rate_variation = {}
    for key, group in keys:
        scores = group["mib_per_second"].to_numpy(dtype=float)
        if len(scores) > 1 and np.isfinite(scores).all() and float(np.mean(scores)) > 0:
            rate_variation["|".join(map(str, key))] = float(
                np.std(scores, ddof=1) / np.mean(scores)
            )
    worst = sorted(rate_variation.items(), key=lambda x: x[1], reverse=True)[:5]

    fatal_checks = {
        "complete_factor_matrix", "distinct_jmh_forks",
        "finite_positive_jmh_scores", "rate_unit_reconciliation",
        "raw_jmh_provenance",
    }
    result = {
        "run": str(run),
        "manifest_disposition": manifest.get("disposition"),
        "checks": findings,
        "raw_jmh_errors": provenance_errors[:30],
        "worst_fork_cv": [{"condition": k, "coefficient_of_variation": v}
                          for k, v in worst],
        "coverage_complete": all(c["passed"] for c in findings if c["check"] == "complete_factor_matrix"),
        "jmh_reconciled": jmh_reconciled,
        "structural_audit_passed": all(
            c["passed"] for c in findings if c["check"] in fatal_checks
        ),
        "publication_ready": False,
        "note": "Audit is read-only; no validation flags or manifests were changed.",
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    parser.add_argument("--out", type=Path, help="Optional audit JSON output path")
    args = parser.parse_args()
    report = audit(args.run)
    encoded = json.dumps(report, indent=2, sort_keys=True)
    print(encoded)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(encoded + "\n")
    return 0 if report.get("structural_audit_passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
