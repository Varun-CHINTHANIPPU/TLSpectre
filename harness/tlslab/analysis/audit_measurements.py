"""Audit main E2-E6 result coverage, row validity and reproducibility hashes.

This is a *structural consistency audit*, NOT independent reproduction of
cryptography, certificate signatures or performance measurements.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

from ..experiment_matrix import plan
from ..evidence import ROOT


EXPERIMENTS = ("E2", "E3", "E4", "E5", "E6")
FACTOR_COLUMNS = {
    "E2": ("provider", "suite", "group"),
    "E3": ("block", "position", "suite", "size", "platform"),
    "E4": ("block", "position", "configuration", "suite"),
    "E5": ("block", "position", "provider", "group", "rtt_ms"),
    "E6": ("block", "position", "status", "must_staple",
           "responder_reachable", "stapling", "freshness", "policy"),
}


class EvidenceAuditError(ValueError):
    pass


def expected_keys(experiment: str) -> set[tuple]:
    if experiment not in EXPERIMENTS:
        raise EvidenceAuditError("unknown main measurement experiment")
    columns = FACTOR_COLUMNS[experiment]
    cases = plan(experiment)
    if experiment == "E6":
        cases = [{**case, "policy": policy} for case in cases
                 for policy in ("K1", "K2", "K3", "K4", "K5")]
    return {tuple(row[field] for field in columns) for row in cases}


def select_unique(root: Path, experiment: str) -> Path:
    base = root/"data/raw"/experiment
    found = []
    for manifest in base.glob("*/manifest.json"):
        try:
            info = json.loads(manifest.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if (info.get("experiment") == experiment
            and info.get("disposition") == "COMPLETE"
            and not info.get("metadata", {}).get("pilot")):
            found.append(manifest.parent)
    if len(found) != 1:
        raise EvidenceAuditError(
            f"{experiment}: expected exactly one complete non-pilot run, found "
            f"{len(found)}; select explicit --run {experiment}=PATH")
    return found[0]


def _all_true(df: pd.DataFrame, column: str) -> bool:
    return column in df and df[column].eq(True).all()


def audit_one(experiment: str, folder: Path) -> dict:
    if experiment not in EXPERIMENTS:
        raise EvidenceAuditError("select only E2 through E6")
    manifest_file, data_file = folder/"manifest.json", folder/"results.parquet"
    if not manifest_file.is_file() or not data_file.is_file():
        raise EvidenceAuditError(f"{experiment}: missing manifest or parquet")
    info = json.loads(manifest_file.read_text())
    if info.get("experiment") != experiment:
        raise EvidenceAuditError(f"{experiment}: manifest experiment mismatch")
    if info.get("metadata", {}).get("pilot") or info.get("disposition") != "COMPLETE":
        raise EvidenceAuditError(f"{experiment}: pilot/partial evidence rejected")
    df = pd.read_parquet(data_file)
    keys = FACTOR_COLUMNS[experiment]
    missing = set(keys) | {"validated"}
    if missing - set(df.columns):
        raise EvidenceAuditError(f"{experiment}: missing fields {missing - set(df.columns)}")
    actual = [tuple(values) for values in df[list(keys)].itertuples(index=False, name=None)]
    frozen = expected_keys(experiment)
    if len(df) != len(frozen) or len(set(actual)) != len(actual) or set(actual) != frozen:
        raise EvidenceAuditError(
            f"{experiment}: duplicate/missing factor keys, expected {len(frozen)}, "
            f"observed {len(actual)}")
    if not _all_true(df, "validated"):
        raise EvidenceAuditError(f"{experiment}: unvalidated rows")
    if "validation_failures" in df and df["validation_failures"].notna().any():
        raise EvidenceAuditError(f"{experiment}: validation_failures not empty")
    # E6 status means CERTIFICATE good/revoked, not a measurement status.
    if experiment != "E6" and "status" in df and not df["status"].eq("MEASURED").all():
        raise EvidenceAuditError(f"{experiment}: failed/nonmeasured rows")
    if experiment == "E2":
        if (not df["n_verified"].eq(50).all()
            or not df["n_expected"].eq(50).all()
            or not df["verification_pass"].eq(1).all()
            or not _all_true(df, "group_verified")):
            raise EvidenceAuditError("E2: 50/50 capture/Finished/group checks not established")
    if experiment == "E3":
        if (not df["cpu_ns_per_byte"].gt(0).all()
            or not _all_true(df, "thermal_ok")
            or not df["throttle_events"].eq(0).all()):
            raise EvidenceAuditError("E3: CPU time/thermal evidence incomplete")
    if experiment == "E4":
        if (not df["mib_per_second"].gt(0).all()
            or not _all_true(df, "suite_verified")
            or not _all_true(df, "record_size_ok")
            or not _all_true(df, "thermal_ok")):
            raise EvidenceAuditError("E4: suite, record or thermal evidence incomplete")
    if experiment == "E5":
        if (not _all_true(df, "tls13_verified")
            or not _all_true(df, "group_verified")
            or not _all_true(df, "resumption_verified")
            or not df["hrr_rate"].eq(0).all()):
            raise EvidenceAuditError("E5: group/HRR/PSK wire evidence incomplete")
    if experiment == "E6":
        if (not _all_true(df, "matches_expectation")
            or not df["outcome"].isin(("ACCEPT", "REJECT")).all()
            or df["staple_observed"].isna().any()):
            raise EvidenceAuditError("E6: policy or staple evidence incomplete")
    return {
        "experiment": experiment, "directory": str(folder), "cells": len(df),
        "disposition": info["disposition"], "git_sha": info.get("git_sha"),
        "hardware": info.get("hardware"),
        "manifest_sha256": hashlib.sha256(manifest_file.read_bytes()).hexdigest(),
        "parquet_sha256": hashlib.sha256(data_file.read_bytes()).hexdigest(),
        "qualification": "structural consistency only; independent scientific replication pending",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=ROOT)
    p.add_argument("--run", action="append", default=[],
                   help="Explicit E2=/absolute/path etc.; repeat for each experiment")
    args = p.parse_args()
    mapping = {}
    for value in args.run:
        experiment, separator, folder = value.partition("=")
        if separator != "=" or experiment not in EXPERIMENTS or not folder or experiment in mapping:
            p.error("--run must be a unique EXPERIMENT=PATH for E2-E6")
        mapping[experiment] = Path(folder)
    results = []
    for name in EXPERIMENTS:
        folder = mapping.get(name) or select_unique(args.root, name)
        results.append(audit_one(name, folder))
    outfile = args.root/"results/reports/E2-E6-structural-audit.json"
    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text(json.dumps({
        "scope": "automated factor completeness and evidence flags; no independent crypto/signature check",
        "experiments": results
    }, indent=2, default=str) + "\n")
    print(json.dumps({"audit": str(outfile),
                      "counts": {r["experiment"]: r["cells"] for r in results}},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
