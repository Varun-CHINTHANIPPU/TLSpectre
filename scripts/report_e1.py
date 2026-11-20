#!/usr/bin/env python3
"""Read-only E1 audit: factor coverage, conformance outcomes and PR15/PR22 evidence.

A COMPLETE manifest means the runner obtained definitive verdicts, not that
all security probes passed. FAIL verdicts are retained as research findings.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
CONFIGS = ("P1", "P2", "B1", "B2", "B3", "A1", "A2", "A3")
PROBES = tuple(f"PR{i:02}" for i in range(1, 23))
OUTCOMES = ("PASS", "FAIL", "N/A", "BLOCKED", "INCONCLUSIVE")


def newest_run() -> Path:
    candidates = [p for p in (ROOT / "data/raw/E1").glob("*")
                  if p.is_dir() and (p / "results.parquet").is_file()]
    if not candidates:
        raise FileNotFoundError("No finalized E1 results.parquet; run E1 first")
    return max(candidates, key=lambda p: p.stat().st_mtime)


def audit(run: Path) -> dict:
    manifest = json.loads((run / "manifest.json").read_text())
    frame = pd.read_parquet(run / "results.parquet")
    required = {"configuration", "repetition", "probe_id", "outcome", "validated"}
    absent = required - set(frame.columns)
    if absent:
        raise ValueError(f"Missing E1 result fields: {sorted(absent)}")

    rows = frame.to_dict("records")
    keys = [(str(r["configuration"]), int(r["repetition"]), str(r["probe_id"]))
            for r in rows]
    key_counts = Counter(keys)
    expected = {(config, repetition, probe)
                for config in CONFIGS for repetition in range(1, 4)
                for probe in PROBES}
    present = set(keys)
    counts = Counter(str(r["outcome"]) for r in rows)
    grouped = defaultdict(Counter)
    per_probe = defaultdict(Counter)
    for r in rows:
        grouped[str(r["configuration"])][str(r["outcome"])] += 1
        per_probe[str(r["probe_id"])][str(r["outcome"])] += 1
    manifest_counts = manifest.get("details", {}).get("counts", {})
    inconsistent = [
        f"{r['configuration']}/{r['repetition']}/{r['probe_id']}: "
        f"outcome={r['outcome']} validated={r['validated']}"
        for r in rows
        if bool(r["validated"]) != (r["outcome"] in ("PASS", "FAIL", "N/A"))
    ]
    observations = []
    raw = run / "raw_evidence.jsonl"
    if raw.is_file():
        for line in raw.open(encoding="utf-8"):
            try:
                item = json.loads(line)
            except ValueError:
                continue
            r = item.get("row", {})
            if r.get("probe_id") in ("PR15", "PR22"):
                observations.append({
                    "configuration": r.get("configuration"),
                    "repetition": r.get("repetition"),
                    "probe_id": r.get("probe_id"),
                    "outcome": r.get("outcome"),
                    "observation": str(item.get("observation", ""))[:1200],
                })
    # Configuration setup failures appear in the Parquet "error" column,
    # not raw_evidence.jsonl: the probe loop never started.
    blocked_errors = []
    seen_errors = set()
    for row in rows:
        if row.get("outcome") != "BLOCKED":
            continue
        error = row.get("error")
        if not isinstance(error, str) or not error.strip():
            continue
        key = (str(row.get("configuration")), str(row.get("repetition")), error)
        if key not in seen_errors:
            seen_errors.add(key)
            blocked_errors.append({
                "configuration": row.get("configuration"),
                "repetition": row.get("repetition"),
                "error": error,
            })
    unexpected = sorted(present - expected)
    duplicates = sorted(k for k, value in key_counts.items() if value != 1)
    mismatched_counts = {
        status: {"manifest": manifest_counts.get(status),
                 "observed": counts.get(status, 0)}
        for status in OUTCOMES
        if manifest_counts.get(status) != counts.get(status, 0)
    } if manifest_counts else {}
    return {
        "run": str(run),
        "manifest_disposition": manifest.get("disposition"),
        "total_rows": len(rows),
        "expected_full_rows": len(expected),
        "full_matrix": len(rows) == len(expected) and present == expected
                       and not duplicates,
        "missing_keys": len(expected - present),
        "unexpected_keys": unexpected[:30],
        "duplicate_keys": duplicates[:30],
        "counts": {s: counts.get(s, 0) for s in OUTCOMES},
        "validated_rows": sum(bool(r["validated"]) for r in rows),
        "manifest_count_mismatches": mismatched_counts,
        "validation_flag_disagreements": inconsistent[:30],
        "by_configuration": {cfg: {s: grouped[cfg].get(s, 0) for s in OUTCOMES}
                             for cfg in CONFIGS},
        "by_probe": {probe: {s: per_probe[probe].get(s, 0) for s in OUTCOMES}
                     for probe in PROBES},
        "blocked_setup_errors": blocked_errors,
        "pr15_pr22_observations": observations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", nargs="?", type=Path, help="E1 run directory; default latest finalized")
    parser.add_argument("--out", type=Path, help="Optional JSON report path")
    args = parser.parse_args()
    report = audit(args.run or newest_run())
    print(f"E1 run: {report['run']}")
    print(f"Manifest: {report['manifest_disposition']}; "
          f"rows: {report['total_rows']}/{report['expected_full_rows']}; "
          f"full matrix: {report['full_matrix']}")
    print("Outcome counts: " + ", ".join(
        f"{s}={n}" for s, n in report["counts"].items()))
    print(f"Validated verdicts: {report['validated_rows']}/{report['total_rows']}")
    print(f"Missing keys: {report['missing_keys']}; "
          f"duplicates: {len(report['duplicate_keys'])}; "
          f"manifest disagreements: {len(report['manifest_count_mismatches'])}")
    print("\nPer-configuration: PASS  FAIL  N/A  BLOCKED  INCONCLUSIVE")
    for cfg, count in report["by_configuration"].items():
        if any(count.values()):
            print(f"{cfg:>4}: " + "  ".join(f"{count[s]:>4}" for s in OUTCOMES))
    print("\nProbes with failures or unresolved results:")
    for probe, count in report["by_probe"].items():
        if count["FAIL"] or count["BLOCKED"] or count["INCONCLUSIVE"]:
            print(f"  {probe}: " + ", ".join(f"{s}={count[s]}" for s in
                  ("FAIL", "BLOCKED", "INCONCLUSIVE") if count[s]))
    if report["blocked_setup_errors"]:
        print("\nBlocked setup errors (one per configuration/repetition):")
        for item in report["blocked_setup_errors"][:30]:
            print(f"  {item['configuration']}/{item['repetition']}: {item['error']}")
    print("\nPR15 / PR22 observed evidence (first 24):")
    for item in report["pr15_pr22_observations"][:24]:
        print(f"  {item['configuration']}/{item['repetition']} "
              f"{item['probe_id']} {item['outcome']}: "
              f"{item['observation'][:260]}")
    if len(report["pr15_pr22_observations"]) > 24:
        print(f"  ... {len(report['pr15_pr22_observations']) - 24} more; "
              "full evidence is retained in raw_evidence.jsonl")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, default=str) + "\n")
        print(f"Saved report: {args.out}")
    if report["validation_flag_disagreements"] or report["manifest_count_mismatches"]:
        print("WARNING: Result/manifest consistency failures; inspect JSON report")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
