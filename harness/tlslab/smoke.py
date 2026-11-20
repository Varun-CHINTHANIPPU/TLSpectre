"""Single-configuration integration run with append-only evidence files.

Starts the local server, probes it, stops it, and preserves its bounded output.
This does not replace E1's full 22-probe active test suite.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import yaml

from .launch import ROOT, build_command
from .probe import run as run_probe


def run_once(config_path: Path, out_dir: Path, ca_file: Path, timeout: float = 20) -> dict:
    if not os.getenv("KS_PASS"):
        raise RuntimeError("KS_PASS must be set")
    if not (ROOT / "java/target/tlslab-server.jar").exists():
        raise FileNotFoundError("Build first: make build")
    cmd, manifest = build_command(config_path)
    resolved = config_path if config_path.is_absolute() else ROOT / config_path
    config = yaml.safe_load(resolved.read_text())
    out_dir.mkdir(parents=True, exist_ok=False)
    log = out_dir / "server.log"
    manifest["started_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["notes"] = "partial E1 smoke probes, no network namespaces or statistically randomized trials"
    manifest["jdk"] = subprocess.run(["java", "-version"], capture_output=True, text=True).stderr.strip()
    manifest["openssl"] = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.strip()
    try:
        manifest["git_sha"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        manifest["git_sha"] = "UNKNOWN"
    result = None
    with log.open("w", encoding="utf-8") as output:
        server = subprocess.Popen(cmd, cwd=ROOT, stdout=output,
                                  stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    raise RuntimeError(f"server exited: {server.returncode}")
                try:
                    with socket.create_connection(
                        (config.get("bindHost", "127.0.0.1"), int(config["httpsPort"])),
                        timeout=0.25
                    ):
                        break
                except OSError:
                    time.sleep(0.15)
            else:
                raise TimeoutError("server did not open HTTPS socket")
            result = run_probe(config, str(ca_file))
            (out_dir / "probe.json").write_text(json.dumps(result, indent=2) + "\n")
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
            manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
            manifest["result"] = "PASS" if result and result["complete"] else "FAIL"
            (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return {"manifest": str(out_dir / "manifest.json"), "passed": bool(result and result["complete"])}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--config", type=Path, default=Path("configs/server/P1.yaml"))
    p.add_argument("--ca-file", type=Path, default=Path("pki/out/ca.crt"))
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    if args.out:
        target = args.out
    else:
        now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = Path("data/raw/E1-smoke") / (now + "_" + str(os.getpid()))
    outcome = run_once(args.config, target, args.ca_file)
    print(json.dumps(outcome, indent=2))
    return 0 if outcome["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
