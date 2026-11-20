"""Exploratory paired-block E3 AEAD throughput contrasts.

Requires a structurally passed, matching full E3 audit. This analysis does
NOT change E3 validated flags or produce publication-gated figures. Each
independent block contributes one ratio for each fixed suite and payload.
We report descriptive percentile block-bootstrap intervals and exploratory
exact two-sided sign tests with Holm correction over the 18 contrasts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats
from statsmodels.stats.multitest import multipletests

from ..experiment_matrix import SUITES


SIZES = (64, 1024, 16384)
BLOCKS = tuple(range(1, 11))
PLATFORMS = ("SunJCE", "BC", "A4", "A5")


def _checked_data(run: Path) -> pd.DataFrame:
    manifest_path = run / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("Missing E3 manifest")
    manifest = json.loads(manifest_path.read_text())
    metadata = manifest.get("metadata", {})
    if (manifest.get("experiment") != "E3" or metadata.get("pilot")
            or metadata.get("replication_design") != "randomized cross-condition blocks"):
        raise ValueError("Requires a full E3 randomized-block run")
    audit_file = run / "audit.json"
    if not audit_file.is_file():
        raise ValueError("Run tlslab.analysis.audit_e3 --out RUN/audit.json first")
    report = json.loads(audit_file.read_text())
    if (Path(report.get("run", "")).resolve() != run.resolve()
            or not report.get("structural_audit_passed")
            or not report.get("jmh_reconciled")
            or not report.get("coverage_complete")):
        raise ValueError("Matching successful E3 structural provenance audit required")
    frame = pd.read_parquet(run / "results.parquet")
    required = {"block", "suite", "size", "platform", "mib_per_second", "status"}
    if required - set(frame.columns):
        raise ValueError("Missing measured E3 columns")
    if len(frame) != 360 or not frame["status"].eq("MEASURED").all():
        raise ValueError("Full measured 360-row matrix required")
    if frame[["block", "suite", "size", "platform"]].duplicated().any():
        raise ValueError("Duplicate fixed-factor observation within a block")
    if frame["mib_per_second"].isna().any():
        raise ValueError("Missing throughput")
    throughput = frame["mib_per_second"].to_numpy(dtype=float)
    if not np.isfinite(throughput).all() or (throughput <= 0).any():
        raise ValueError("Non-finite or non-positive throughput")
    intended = {
        (block, suite, size, platform)
        for block in BLOCKS for suite in SUITES for size in SIZES
        for platform in PLATFORMS
    }
    observed = {
        (int(b), str(s), int(size), str(p))
        for b, s, size, p in frame[
            ["block", "suite", "size", "platform"]
        ].itertuples(index=False, name=None)
    }
    if observed != intended:
        raise ValueError("E3 fixed-factor or randomized-block coverage incomplete")
    return frame


def contrast_table(frame: pd.DataFrame, *, bootstrap_samples: int = 20000,
                   seed: int = 20261117) -> pd.DataFrame:
    """One paired ratio per block; never pool suites or payload sizes."""
    if bootstrap_samples < 100:
        raise ValueError("At least 100 bootstrap samples required")
    rng = np.random.default_rng(seed)
    rows = []
    for suite in SUITES:
        for size in SIZES:
            sub = frame[(frame["suite"] == suite) & (frame["size"] == size)]
            wide = sub.pivot(index="block", columns="platform", values="mib_per_second")
            wide = wide.reindex(index=BLOCKS, columns=PLATFORMS)
            if wide.isna().any().any():
                raise ValueError("Missing paired blocks for a condition")
            base = wide["SunJCE"].to_numpy(dtype=float)
            comparisons = ("BC", "A5" if "CHACHA20" in suite else "A4")
            for target in comparisons:
                values = wide[target].to_numpy(dtype=float)
                ratios = values / base
                # Sign test tests median ratio=1; exact equality is a tie.
                # Avoid close-to-one tolerance that could hide real outcomes.
                positive = int(np.count_nonzero(ratios > 1))
                negative = int(np.count_nonzero(ratios < 1))
                non_ties = positive + negative
                p = float(stats.binomtest(
                    positive, non_ties, p=0.5, alternative="two-sided"
                ).pvalue) if non_ties else 1.0
                sample_ids = rng.integers(
                    0, len(ratios), size=(bootstrap_samples, len(ratios))
                )
                medians = np.median(ratios[sample_ids], axis=1)
                ci_low, ci_high = np.quantile(medians, (0.025, 0.975))
                rows.append({
                    "suite": suite, "size": int(size),
                    "comparison": target + "/SunJCE",
                    "n_blocks": len(ratios),
                    "median_ratio": float(np.median(ratios)),
                    "min_ratio": float(np.min(ratios)),
                    "max_ratio": float(np.max(ratios)),
                    "ci_low_percentile": float(ci_low),
                    "ci_high_percentile": float(ci_high),
                    "n_above_1": positive,
                    "n_below_1": negative,
                    "n_equal_1": len(ratios) - non_ties,
                    "p_sign_exact": p,
                })
    table = pd.DataFrame(rows)
    if len(table) != 18:
        raise ValueError("Expected exactly 18 contrasts")
    table["p_holm_18"] = multipletests(table["p_sign_exact"].to_numpy(),
                                      method="holm")[1]
    return table


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("run", type=Path, help="Existing audited E3 full run directory")
    p.add_argument("--out", type=Path, help="Output CSV path (default RUN/e3_contrasts.csv)")
    ns = p.parse_args()
    run = ns.run
    frame = _checked_data(run)
    table = contrast_table(frame)
    output = ns.out or run / "e3_contrasts.csv"
    output.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(output, index=False)
    print(table.round({
        "median_ratio": 3, "min_ratio": 3, "max_ratio": 3,
        "ci_low_percentile": 3, "ci_high_percentile": 3,
        "p_sign_exact": 5, "p_holm_18": 5,
    }).to_string(index=False))
    print(json.dumps({
        "output": str(output), "comparisons": len(table),
        "n_blocks": 10, "exploratory": True, "publication_ready": False,
        "tests": "two-sided exact sign test of block ratio vs 1; Holm over 18",
        "intervals": "95% percentile bootstrap of paired block median ratios (20,000 resamples)",
        "limitations": [
            "CPU governor/turbo not controlled",
            "thermal stability unverified",
            "CPU time per byte not measured",
            "JDK 21 AEAD microbenchmark, not full TLS throughput",
            "n=10 randomized blocks on one host; CIs conditional on measured environment",
        ]
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
