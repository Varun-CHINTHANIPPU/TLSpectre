"""Append-only experiment manifests and typed Parquet results.

Requires pyarrow; never silently fall back to lossy CSV for research outputs.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import platform
import psutil
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version(command: list[str]) -> str:
    try:
        run = subprocess.run(command, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"UNAVAILABLE: {type(exc).__name__}"
    return ((run.stdout or run.stderr).strip().splitlines() or ["EMPTY"])[0][:300]


def new_run(experiment: str, metadata: dict | None = None, *,
            collection: str = "raw") -> Path:
    if experiment not in {"E1", "E2", "E3", "E4", "E5", "E6", "E7"}:
        raise ValueError("invalid experiment name")
    if collection not in {"raw", "references"}:
        raise ValueError("invalid experiment collection")
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "data" / collection / experiment / (now + "_" + uuid.uuid4().hex[:12])
    out.mkdir(parents=True, exist_ok=False)
    from .env import cpu_manifest
    hardware = {
        "cpu_model": next((line.split(":",1)[1].strip()
                           for line in Path("/proc/cpuinfo").read_text().splitlines()
                           if line.startswith("model name")), "UNKNOWN")
                      if Path("/proc/cpuinfo").exists() else "UNKNOWN",
        "cpu_count": psutil.cpu_count(logical=True),
        "ram_bytes": psutil.virtual_memory().total,
        "platform": platform.platform(),
        "kernel": platform.release(),
        "cpu_controls": cpu_manifest(),
    }
    (out / "manifest.json").write_text(json.dumps({
        "experiment": experiment,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "git_sha": version(["git", "rev-parse", "HEAD"]),
        "java": version(["java", "-version"]),
        "openssl": version(["openssl", "version"]),
        "tshark": version(["tshark", "--version"]),
        "nginx": version(["nginx", "-v"]),
        "metadata": metadata or {},
        "hardware": hardware,
        "disposition": "INCOMPLETE",
    }, indent=2) + "\n")
    return out


def append_jsonl(path: Path, row: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(row, sort_keys=True) + "\n")


def to_parquet(rows: list[dict], path: Path):
    if not rows:
        raise ValueError("no experiment rows to serialize")
    import pyarrow as pa
    import pyarrow.parquet as pq
    path.parent.mkdir(parents=True, exist_ok=True)
    # Convert heterogeneous factor fields to JSON separately if needed; all
    # values must be scalars here, never arrays/dicts or secret bytes.
    # Crucial: Arrow infers fields from the first row only. Later failures may
    # introduce an "error" column; silently dropping it destroys evidence.
    keys = sorted(set().union(*(row.keys() for row in rows)))
    normalized = [{
        k: (None if row.get(k) is None else
            row[k] if isinstance(row[k], (bool, int, float, str)) else str(row[k]))
        for k in keys} for row in rows]
    table = pa.Table.from_pylist(normalized)
    pq.write_table(table, path, compression="zstd")
    return len(normalized)


def complete_manifest(folder: Path, disposition: str, details: dict):
    if disposition not in ("COMPLETE", "PARTIAL", "FAILED"):
        raise ValueError("invalid disposition")
    path = folder / "manifest.json"
    data = json.loads(path.read_text())
    data.update({"disposition": disposition, "completed_utc":
                 datetime.now(timezone.utc).isoformat(), "details": details})
    path.write_text(json.dumps(data, indent=2) + "\n")
