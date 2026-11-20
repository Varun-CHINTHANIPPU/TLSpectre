"""Evidence-gated comparison of original E7 and independent nginx B3 reference.

Never pool reference observations into E7's 180 primary observations; runs
were executed in different blocks of wall-clock time, so numeric block IDs
are NOT legitimate paired experimental units across the two stacks.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import pandas as pd

from ..experiment_matrix import plan
from ..evidence import ROOT


class ReferenceEvidenceError(ValueError):
    pass


KEY = ("block", "stapling", "rtt_ms")
THERMAL_SCOPE = "timed client batch + same-process untimed client warm-up"
EXPECTED = set(tuple(row[k] for k in KEY) for row in plan("E7"))


def _load(folder: Path, *, reference: bool) -> tuple[dict, pd.DataFrame]:
    manifest_path = folder/"manifest.json"
    parquet = folder/"results.parquet"
    if not manifest_path.is_file() or not parquet.is_file():
        raise ReferenceEvidenceError(f"missing manifest/results: {folder}")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("experiment") != "E7":
        raise ReferenceEvidenceError("not an E7 run")
    meta = manifest.get("metadata", {})
    if bool(meta.get("reference_only")) != reference:
        raise ReferenceEvidenceError("wrong E7 dataset type")
    if meta.get("pilot") or not meta.get("isolated"):
        raise ReferenceEvidenceError("pilot/non-isolated observations are not publication evidence")
    if reference and manifest.get("disposition") != "COMPLETE":
        raise ReferenceEvidenceError("independent B3 reference is not COMPLETE")
    if not reference and manifest.get("disposition") not in ("PARTIAL", "COMPLETE"):
        raise ReferenceEvidenceError("main E7 manifest is not finalized")
    frame = pd.read_parquet(parquet)
    if len(frame) != 180:
        raise ReferenceEvidenceError(f"expected 180 E7 factor cells, found {len(frame)}")
    required = set(KEY) | {
        "validated", "status", "handshake_ms", "n_handshakes",
        "staple_state_verified", "full_handshake_verified", "thermal_ok",
        "thermal_window_scope"}
    if required - set(frame):
        raise ReferenceEvidenceError("missing evidence columns: " +
                                     ", ".join(sorted(required - set(frame))))
    if frame[list(required)].isnull().any().any():
        raise ReferenceEvidenceError("null factor, timing or validation evidence")
    if (not frame["validated"].eq(True).all() or
        not frame["status"].eq("MEASURED").all() or
        not frame["staple_state_verified"].eq(True).all() or
        not frame["full_handshake_verified"].eq(True).all() or
        not frame["thermal_ok"].eq(True).all()):
        raise ReferenceEvidenceError("one or more E7 rows are not validated")
    keys = [tuple(x) for x in frame[list(KEY)].itertuples(index=False, name=None)]
    if len(set(keys)) != 180 or set(keys) != EXPECTED:
        raise ReferenceEvidenceError("duplicated or missing E7 factor tuples")
    if not frame["thermal_window_scope"].eq(THERMAL_SCOPE).all():
        raise ReferenceEvidenceError(
            "E7 thermal window scope mismatch or legacy broad window: "
            "re-execute main and reference with a common measurement definition")
    if frame["handshake_ms"].le(0).any():
        raise ReferenceEvidenceError("invalid handshake timing")
    expected_counts = frame["stapling"].map({"cold": 1, "warm": 500, "off": 500})
    if not frame["n_handshakes"].eq(expected_counts).all():
        raise ReferenceEvidenceError("unexpected number of timed handshakes")
    if reference and not frame["stack"].eq("nginx/OpenSSL B3").all():
        raise ReferenceEvidenceError("reference contains an unknown TLS stack")
    return manifest, frame


def audit(main: Path, reference: Path) -> pd.DataFrame:
    original, a = _load(main, reference=False)
    other, b = _load(reference, reference=True)
    hardware_a, hardware_b = original.get("hardware", {}), other.get("hardware", {})
    for item in ("cpu_model", "cpu_count"):
        if not hardware_a.get(item) or hardware_a.get(item) != hardware_b.get(item):
            raise ReferenceEvidenceError(f"different/missing experimental host {item}")
    if original.get("java") != other.get("java"):
        raise ReferenceEvidenceError("different JDK environments for client timing")
    if original.get("openssl") != other.get("openssl"):
        raise ReferenceEvidenceError("different OpenSSL environment")
    if original.get("nginx") != other.get("nginx"):
        raise ReferenceEvidenceError("different nginx environment")
    original_tuning = original.get("details", {}).get("cpu_tuning")
    reference_tuning = other.get("details", {}).get("cpu_tuning")
    if (not isinstance(original_tuning, dict) or
        not isinstance(reference_tuning, dict) or
        original_tuning != reference_tuning):
        raise ReferenceEvidenceError(
            "missing or different effective CPU governor/turbo controls "
            "between Java and B3 reference runs")
    # The row labels identify the same *factor levels*, but the reference
    # was measured on a separate run: no invalid block-wise paired test.
    summary = (a.groupby(["stapling", "rtt_ms"], as_index=False)["handshake_ms"]
               .agg(main_median_ms="median", main_n="count"))
    ref_summary = (b.groupby(["stapling", "rtt_ms"], as_index=False)["handshake_ms"]
                   .agg(reference_median_ms="median", reference_n="count"))
    result = summary.merge(ref_summary, on=["stapling", "rtt_ms"], validate="one_to_one")
    if len(result) != 6 or not result["main_n"].eq(30).all() or not result["reference_n"].eq(30).all():
        raise ReferenceEvidenceError("six complete 30-block conditions not found")
    result["reference_over_main_ratio"] = result["reference_median_ms"] / result["main_median_ms"]
    result["comparison_scope"] = "unpaired descriptive cross-run; no causal or paired significance claim"
    return result.sort_values(["stapling", "rtt_ms"])


def find_unique(root: Path, *, reference: bool) -> Path:
    base = root/"data"/("references" if reference else "raw")/"E7"
    candidates = []
    for manifest in base.glob("*/manifest.json"):
        try:
            data = json.loads(manifest.read_text())
            meta = data.get("metadata", {})
            if (meta.get("pilot") is False and
                bool(meta.get("reference_only")) == reference):
                candidates.append(manifest.parent)
        except (ValueError, OSError):
            continue
    if len(candidates) != 1:
        raise ReferenceEvidenceError(
            f"Select explicit E7 {'B3 reference' if reference else 'main'} directory: "
            f"found {len(candidates)} non-pilot runs under {base}")
    return candidates[0]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--main", type=Path, default=None, help="original 180-row E7 run")
    p.add_argument("--reference", type=Path, default=None, help="independent nginx B3 run")
    p.add_argument("--root", type=Path, default=ROOT)
    args = p.parse_args()
    original = args.main or find_unique(args.root, reference=False)
    comparison = args.reference or find_unique(args.root, reference=True)
    result = audit(original, comparison)
    target = args.root/"results/tables/E7-B3-reference.csv"
    target.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(target, index=False)
    report = target.with_suffix(".audit.json")
    report.write_text(json.dumps({
        "original_run": str(original), "reference_run": str(comparison),
        "rows_per_stack": 180,
        "statistical_scope": "descriptive unpaired cross-run; no causal/paired inference",
        "publication_limitations": ["signature not independently verified by s_client",
                                    "reference has a short-lived distinct server certificate",
                                    "reference and main not interleaved in randomized blocks"],
        "output": str(target)
    }, indent=2) + "\n")
    print(json.dumps({"table": str(target), "audit": str(report)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
