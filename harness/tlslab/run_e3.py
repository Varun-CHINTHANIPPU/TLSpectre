"""E3: 36 AEAD conditions × 10 seeded randomized blocks.

One independent JMH fork per condition per block, rather than ten adjacent
forks for one condition. Runs remain unvalidated pending CPU/thermal audit.
"""
import argparse
import json
import os
from pathlib import Path
from datetime import datetime, timezone
import statistics
import subprocess

from .env import (managed_host_tuning, experiment_affinity, pinned, performance_snapshot,
                  controls_established, require_jdk, ThermalWindow,
                  tuning_preflight)
from .evidence import new_run, append_jsonl, to_parquet, complete_manifest
from .experiment_matrix import plan
from .launch import ROOT


AEAD = {
    "TLS_AES_128_GCM_SHA256":"AES-128-GCM",
    "TLS_AES_256_GCM_SHA384":"AES-256-GCM",
    "TLS_CHACHA20_POLY1305_SHA256":"CHACHA20-POLY1305",
}
ABLATIONS = {
    "A4":["-XX:+UnlockDiagnosticVMOptions","-XX:-UseAES",
          "-XX:-UseAESIntrinsics","-XX:-UseAESCTRIntrinsics","-XX:-UseGHASHIntrinsics"],
    "A5":["-XX:+UnlockDiagnosticVMOptions","-XX:-UseChaCha20Intrinsics",
          "-XX:-UsePoly1305Intrinsics"],
}


def fork_rows(jmh: dict, cell: dict):
    params = jmh.get("params", {})
    metric = jmh["primaryMetric"]
    raw = metric.get("rawData", [])
    if not raw or not all(isinstance(f, list) and f for f in raw):
        raise ValueError("JMH per-fork rawData unavailable; cannot claim n independent samples")
    if metric["scoreUnit"] != "ops/s":
        raise ValueError("JMH score unit is not ops/s")
    secondary = jmh.get("secondaryMetrics", {})
    cpu_raw = secondary.get("cpuNanos", {}).get("rawData", [])
    byte_raw = secondary.get("bytes", {}).get("rawData", [])
    rows=[]
    for fork, values in enumerate(raw):
        score = statistics.mean(values)
        if score <= 0:
            raise ValueError("invalid throughput")
        size = cell["size"]
        cpu_ns_per_byte = None
        if fork < len(cpu_raw) and fork < len(byte_raw):
            # Benchmark-thread CPU time / bytes encrypted, measurement iterations only.
            cpu_total, byte_total = sum(cpu_raw[fork]), sum(byte_raw[fork])
            if cpu_total > 0 and byte_total > 0 and len(cpu_raw[fork]) == len(values):
                cpu_ns_per_byte = cpu_total / byte_total
        rows.append({**cell, "fork":fork+1, "ops_per_second":score,
                     "mib_per_second":score*size/1048576,
                     "wall_ns_per_byte":1e9/(score*size),
                     "cpu_ns_per_byte":cpu_ns_per_byte,
                     "cpu_time_source":"ThreadMXBean per JMH iteration" if cpu_ns_per_byte else None,
                     "score_unit":"ops/s", "status":"MEASURED", "validated":False})
    return rows


def validation_failures(row: dict, *, pilot: bool, jdk: int, controls: tuple[bool, bool]) -> list[str]:
    """Every reason this E3 observation cannot be used as validated evidence."""
    reasons = []
    if pilot:
        reasons.append("pilot run")
    if row.get("status") != "MEASURED":
        reasons.append("not measured")
    if not row.get("cpu_ns_per_byte"):
        reasons.append("cpu_ns_per_byte missing")
    if jdk < 27:
        reasons.append(f"JDK {jdk} < 27")
    if not all(controls):
        reasons.append("performance governor / turbo-off not established at start and end")
    if not row.get("thermal_ok"):
        reasons.append("thermal: " + (row.get("thermal_reason") or "not recorded"))
    return reasons


def selected_schedule(*, pilot: bool) -> list[dict]:
    """Freeze order; pilot compares stock SunJCE with one ablated configuration.

    Taking the first two seeded positions accidentally selects two A5 cells,
    hiding whether an A5-specific JVM flag or all JMH runs are failing.
    """
    cells = plan("E3", blocks=1 if pilot else 10)
    if not pilot:
        return cells
    reference = next(cell for cell in cells if cell["platform"] == "SunJCE")
    ablated = next(cell for cell in cells if cell["platform"] == "A5")
    return sorted((reference, ablated), key=lambda cell: cell["position"])


def execute(*, pilot=False, tune_cpu=False):
    bench = ROOT/"java/bench/target/benchmarks.jar"
    if not bench.is_file():
        raise FileNotFoundError("Run make bench before E3")
    if not pilot and not tune_cpu:
        raise ValueError("Full E3 requires --tune-cpu (root): the audit needs the performance "
                         "governor and turbo disabled for the whole run")
    if tune_cpu:
        tuning_preflight()
    jdk = require_jdk(27, "E3")
    schedule = selected_schedule(pilot=pilot)
    out = new_run("E3", {
        "jdk_feature": jdk,
        "pilot": pilot, "planned_cells": len(schedule),
        "expected_blocks": 1 if pilot else 10,
        "jmh_forks_per_condition_per_block": 1,
        "replication_design": "randomized cross-condition blocks",
        "block_order_seed": "Python random.Random(block_id)",
        "cpu_ns_per_byte_measured": True,
        "cpu_tuning_requested": tune_cpu,
        "cpu_pinning_requested": bool(os.getenv("TLSLAB_PIN_CPU", "").strip()),
    })
    # JMH creates a lock in java.io.tmpdir. A user-owned /tmp/jmh.lock
    # can be denied to sudo/root by Linux protected_regular. Use private
    # scratch storage for this run; do not delete the global lock or bypass it.
    jmh_tmp = out / "jmh-tmp"
    jmh_tmp.mkdir(parents=True, mode=0o700, exist_ok=True)
    append_jsonl(out/"schedule.jsonl", {"index": 0, "total": len(schedule),
                 "planned": schedule, "frozen_utc": datetime.now(timezone.utc).isoformat()})
    rows = []
    with managed_host_tuning(tune_cpu) as tuning:
        start_snapshot = performance_snapshot()
        append_jsonl(out/"environment.jsonl", {"phase": "start", "tuning": tuning,
                                              "cpu": start_snapshot})
        cores = experiment_affinity()["server"]
        for index, cell in enumerate(schedule):
            block = int(cell["block"])
            platform = cell["platform"]
            flags = ABLATIONS.get(platform, [])
            provider = "BC" if platform == "BC" else "SunJCE"
            result_file = out/"jmh"/f"{index:04d}.json"
            result_file.parent.mkdir(parents=True, exist_ok=True)
            cmd = ["java", f"-Djava.io.tmpdir={jmh_tmp}", "-jar", str(bench),
                   "lab.tls13.bench.AeadBench.encrypt",
                   "-p", f"aead={AEAD[cell['suite']]}",
                   "-p", f"size={cell['size']}",
                   "-p", f"provider={provider}",
                   "-f", "1",
                   "-wi", str(1 if pilot else 5),
                   "-i", str(1 if pilot else 10),
                   "-w", "1s" if pilot else "2s",
                   "-r", "1s" if pilot else "2s",
                   "-rf", "json", "-rff", str(result_file)]
            if flags:
                cmd += ["-jvmArgsAppend", " ".join(flags)]
            if cores:
                cmd = pinned(cmd, cores)
            thermal = ThermalWindow()   # cool-down gate, then throttle counters
            snapshot_before = performance_snapshot()
            started = datetime.now(timezone.utc).isoformat()
            status = {**cell, "platform": platform}
            stdout_log = out/"logs"/f"{index:04d}.stdout.log"
            stderr_log = out/"logs"/f"{index:04d}.stderr.log"
            stdout_log.parent.mkdir(parents=True, exist_ok=True)
            process = None
            try:
                process = subprocess.run(cmd, cwd=ROOT, capture_output=True,
                                         text=True, timeout=150 if pilot else 650)
                stdout_log.write_text(process.stdout)
                stderr_log.write_text(process.stderr)
                if process.returncode != 0:
                    diagnostic = (process.stderr.strip() or process.stdout.strip())
                    raise RuntimeError(
                        f"JMH exited {process.returncode}: {diagnostic[-700:]}"
                    )
                raw = json.loads(result_file.read_text())
                if len(raw) != 1:
                    raise ValueError("JMH should produce exactly one parametrized benchmark")
                extracted = fork_rows(raw[0], status)
                if len(extracted) != 1:
                    raise ValueError("Expected exactly one independent JMH fork for one block")
                # Replicate 1..10 means block ID, not JMH's local fork index.
                extracted[0]["jmh_fork"] = 1
                extracted[0]["fork"] = block
                window = thermal.close()
                extracted[0]["thermal_ok"] = window["ok"]
                extracted[0]["thermal_reason"] = "; ".join(window["reasons"]) or None
                extracted[0]["throttle_events"] = window["throttle_events"]
                extracted[0]["package_temp_before_c"] = window["gate"]["temp_c"]
                extracted[0]["package_temp_after_c"] = window["temp_after_c"]
                rows.extend(extracted)
                append_jsonl(out/"evidence.jsonl", {
                    "cell": index, "block": block, "position": cell["position"],
                    "status": "MEASURED", "forks": 1,
                    "cpu_pinning": cores, "flags": flags,
                    "file": str(result_file), "command": cmd,
                    "stdout_log": str(stdout_log), "stderr_log": str(stderr_log),
                    "returncode": process.returncode,
                    "started_utc": started,
                    "ended_utc": datetime.now(timezone.utc).isoformat(),
                    "cpu_before": snapshot_before, "cpu_after": performance_snapshot(),
                    "thermal": window,
                })
            except Exception as exc:
                error = type(exc).__name__ + ": " + str(exc)[:1200]
                rows.append({**status, "status": "FAILED", "validated": False,
                             "mib_per_second": None, "error": error})
                append_jsonl(out/"evidence.jsonl", {
                    "cell": index, "block": block, "position": cell["position"],
                    "status": "FAILED", "error": error,
                    "flags": flags, "file": str(result_file), "command": cmd,
                    "stdout_log": str(stdout_log), "stderr_log": str(stderr_log),
                    "returncode": process.returncode if process is not None else None,
                    "started_utc": started, "ended_utc": datetime.now(timezone.utc).isoformat(),
                    "cpu_before": snapshot_before, "cpu_after": performance_snapshot(),
                })
                print(f"E3 cell {index} (block {block}, {platform}, {cell['suite']}, {cell['size']} B) "
                      f"FAILED: {error}", flush=True)
        end_snapshot = performance_snapshot()
        append_jsonl(out/"environment.jsonl", {"phase": "end", "cpu": end_snapshot})
    controls = (controls_established(start_snapshot["cpu_controls"]),
                controls_established(end_snapshot["cpu_controls"]))
    for row in rows:
        reasons = validation_failures(row, pilot=pilot, jdk=jdk, controls=controls)
        row["validated"] = not reasons
        row["validation_failures"] = "; ".join(reasons) or None
    to_parquet(rows, out/"results.parquet")
    measured_count = sum(r["status"] == "MEASURED" for r in rows)
    failed_count = sum(r["status"] == "FAILED" for r in rows)
    validated_count = sum(bool(r["validated"]) for r in rows)
    complete = (not pilot and len(rows) == 360 and validated_count == 360)
    complete_manifest(out, "FAILED" if failed_count == len(rows) else
                      "COMPLETE" if complete else "PARTIAL", {
        "measured_forks": measured_count,
        "failures": failed_count,
        "validated": validated_count,
        "cpu_controls_start_end": controls,
        "replication_design": "one independent JMH process/fork per condition per randomized block",
        "validation_rule": "measured, cpu_ns_per_byte present, JDK>=27, governor/turbo at start+end, "
                           "cool-down gate met and zero thermal-throttle events per cell",
    })
    return out


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--pilot",action="store_true")
    p.add_argument("--tune-cpu",action="store_true")
    args=p.parse_args()
    print(execute(pilot=args.pilot,tune_cpu=args.tune_cpu))


if __name__=="__main__":
    main()
