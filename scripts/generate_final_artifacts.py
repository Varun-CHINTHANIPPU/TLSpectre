#!/usr/bin/env python3
"""Generate F1-F6 and T1-T7 from explicitly selected local, gitignored runs.

No raw evidence is modified or copied into Git. The strict artifact generator
runs against a disposable symlink view so historical partial runs cannot be
silently pooled with selected complete runs.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

EXPERIMENTS = tuple(f"E{i}" for i in range(1, 8))
EXPECTED = {"figures": {f"F{i}.pdf" for i in range(1, 7)},
            "tables": {f"T{i}.csv" for i in range(1, 8)}}
ROOT = Path(__file__).resolve().parents[1]


def _source(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"Selected evidence must be inside repository: {relative}")
    if not (candidate / "manifest.json").is_file():
        raise FileNotFoundError(f"Missing manifest for {relative}")
    if not (candidate / "results.parquet").is_file():
        raise FileNotFoundError(f"Missing Parquet evidence for {relative}")
    return candidate


def generate(root: Path, selection: Path) -> None:
    settings = json.loads(selection.read_text())
    runs = settings["runs"]
    reference = settings["e7_reference"]
    if set(runs) != set(EXPERIMENTS):
        raise ValueError(f"Select exactly E1-E7; got {sorted(runs)}")

    with tempfile.TemporaryDirectory(prefix="tls-artifacts-") as temporary:
        view = Path(temporary)
        configs = view / "configs"
        configs.mkdir(parents=True)
        (configs / "server").symlink_to(root / "configs/server", target_is_directory=True)

        for experiment, relative in runs.items():
            source = _source(root, relative)
            manifest = json.loads((source / "manifest.json").read_text())
            if manifest.get("experiment") != experiment:
                raise ValueError(f"{relative}: wrong experiment in manifest")
            destination = view / "data/raw" / experiment
            destination.mkdir(parents=True)
            (destination / source.name).symlink_to(source, target_is_directory=True)

        source = _source(root, reference)
        destination = view / "data/references/E7"
        destination.mkdir(parents=True)
        (destination / source.name).symlink_to(source, target_is_directory=True)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "harness") + (
            os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
        )
        cmd = [sys.executable, "-m", "tlslab.analysis.artifacts",
               "--figures", "--tables", "--strict", "--root", str(view)]
        subprocess.run(cmd, cwd=root, env=env, check=True)

        for kind, filenames in EXPECTED.items():
            produced = {p.name for p in (view / "results" / kind).iterdir()
                        if p.is_file()}
            if produced != filenames:
                raise RuntimeError(f"{kind}: expected {sorted(filenames)}, "
                                   f"got {sorted(produced)}")

        # All strict gates and completeness checks passed before copying.
        for kind, filenames in EXPECTED.items():
            target = root / "results" / kind
            target.mkdir(parents=True, exist_ok=True)
            for filename in sorted(filenames):
                shutil.copy2(view / "results" / kind / filename, target / filename)
                print(f"SAVED: {target / filename}")

        report = root / "results/reports/artifact-selection.json"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps({
            "selection_file": str(selection),
            "runs": runs,
            "e7_reference": reference,
            "method": "explicit-run disposable view; strict artifact gates",
            "note": "local evidence only; no independent scientific replication"
        }, indent=2) + "\n")
        print("SUCCESS: F1-F6 and T1-T7 generated from selected runs.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path,
                        default=ROOT / "configs/artifact-selection.example.json",
                        help="JSON with runs E1-E7 and e7_reference (repo-relative paths)")
    args = parser.parse_args()
    generate(ROOT, args.selection.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
