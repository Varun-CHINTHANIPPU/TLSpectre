"""E4 end-to-end 12-condition AES/ChaCha throughput runner.

No results are generated until a local JDK 27 server, PKI and Java client work.
Run with --pilot before full 20-block execution. Intrinsics are taken from A4/A5.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import re
import subprocess
import os
from pathlib import Path
import time

import yaml

from .env import managed_host_tuning, experiment_affinity, verify_affinity, ThermalWindow
from .evidence import new_run, append_jsonl, to_parquet, complete_manifest, sha256_file
from .experiment_matrix import plan
from .experiment_control import (ephemeral_server_profile, running_server, run_bulk_with_server_cpu,
                                 run_java_csv)
from .wire_capture import wire_proxy, record_size_summary, connections
from .launch import ROOT


def execute(*, pilot=False, blocks=None, tune_cpu=False):
    completed = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=10)
    version_output = completed.stderr + completed.stdout
    match = re.search(r'version "(?:1\.)?(\d+)', version_output)
    if completed.returncode != 0 or not match or int(match.group(1)) < 27:
        raise RuntimeError("E4 requires JDK 27 or later; selected Java runtime: " + version_output.splitlines()[0] if version_output.splitlines() else "E4 requires JDK 27 or later; java -version unavailable")
    if not os.environ.get("KS_PASS"):
        raise ValueError("set KS_PASS and generate lab PKI before experiments")
    if not (ROOT/"java/target/tlslab-server.jar").is_file():
        raise FileNotFoundError("make build first")
    affinity = experiment_affinity()
    rows = plan("E4", blocks=(1 if pilot else blocks))
    run_dir = new_run("E4", {"pilot": pilot, "conditions":12,
                              "planned_blocks": 1 if pilot else blocks or 20,
                              "body_bytes": 1048576 if pilot else 536870912,
                              "warmup_bytes": 262144 if pilot else 67108864})
    data = []
    with managed_host_tuning(tune_cpu) as environment:
        for number, cond in enumerate(rows):
            base = cond["configuration"]
            suite = cond["suite"]
            profile_name = base if base in ("A4", "A5") else "P1" if base=="P1" else "P2"
            profile = ephemeral_server_profile(profile_name, {
                "cipherSuites": [suite], "namedGroups": ["x25519"],
                "ocspStapling": False, "maxPayloadBytes": 536870912,
            }, run_dir/"profiles"/f"{cond['block']}-{number}")
            measurement = {**cond, "condition": base, "suite": suite,
                           "profile_sha256": sha256_file(profile),
                           "status": "INCOMPLETE", "validated": False}
            provider = "SunJSSE" if base != "P2" else "BCJSSE"
            try:
                with running_server(profile, run_dir/"logs"/f"{cond['block']}-{number}.log",
                                    server_affinity=affinity["server"]) as server:
                    arguments = ["127.0.0.1", "8443", "lab.test", provider,
                                 suite, str(1048576 if pilot else 536870912),
                                 str(262144 if pilot else 67108864),
                                 str(ROOT/"pki/out/truststore.p12")]
                    thermal = ThermalWindow()
                    value = run_bulk_with_server_cpu(server.pid, arguments,
                                                     timeout=90 if pilot else 360,
                                                     client_affinity=affinity["client"])
                    window = thermal.close()
                    # Read back every server thread's mask after the transfer:
                    # JIT, GC and Jetty pool threads all exist by now.
                    pinning = verify_affinity(server.pid, affinity["server"])
                    append_jsonl(run_dir/"affinity.jsonl", {"cell": number, **pinning})
                    # Separate, untimed transfer through a byte-exact capture
                    # proxy: what record sizes does this stack actually send?
                    wire_dir = run_dir/"wire"/f"{cond['block']}-{number}"
                    probe_bytes = 4 << 20
                    with wire_proxy("127.0.0.1", 8443, wire_dir) as (host, port):
                        run_java_csv("BulkClient", [host, str(port), "lab.test", provider, suite,
                                                    str(probe_bytes), str(1 << 20),
                                                    str(ROOT/"pki/out/truststore.p12")], timeout=120)
                    conns = connections(wire_dir)
                    if len(conns) != 1:
                        raise RuntimeError(f"expected one captured verification connection, got {len(conns)}")
                    sizes = record_size_summary(conns[0], minimum_body=probe_bytes)
                    append_jsonl(run_dir/"evidence.jsonl", {"cell": number, "thermal": window,
                                                           "record_sizes": sizes, "affinity": pinning})
                    measurement.update({
                        "server_threads": pinning["threads"],
                        "server_affinity_verified": pinning.get("all_threads_confined"),
                        "status": "MEASURED",
                        "measured_bytes": int(value["measured_bytes"]),
                        "mib_per_second": float(value["mib_per_second"]),
                        "client_cpu_ns_per_byte": float(value["client_cpu_ns_per_byte"]),
                        "server_cpu_ns_per_byte": float(value["server_cpu_ns_per_byte"]),
                        "handshake_ns": int(value["handshake_ns"]),
                        "suite": value["suite"],
                        "suite_verified": value["suite"] == suite,
                        "record_size_ok": sizes["ok"],
                        "max_record_ciphertext": sizes["max_record_ciphertext"],
                        "records_per_mib": sizes["records_per_mib"],
                        "large_record_byte_fraction": sizes["large_record_byte_fraction"],
                        "thermal_ok": window["ok"],
                        "thermal_reason": "; ".join(window["reasons"]) or None,
                        "throttle_events": window["throttle_events"],
                    })
            except Exception as exc:
                measurement.update({"status": "FAILED", "error": type(exc).__name__ + ":" + str(exc)[:2500]})
            append_jsonl(run_dir/"measurements.jsonl", measurement)
            data.append(measurement)
            if not pilot and len(data) % 12 == 0:
                time.sleep(15)  # extra rest between blocks; ThermalWindow gates each cell
    expected_rows = 12 * (1 if pilot else (blocks or 20))
    for row in data:
        reasons = validation_failures(row, pilot=pilot, pinning_requested=bool(affinity["server"]))
        row["validated"] = not reasons
        row["validation_failures"] = "; ".join(reasons) or None
    if data:
        to_parquet(data, run_dir/"results.parquet")
    validated = sum(bool(r["validated"]) for r in data)
    complete_manifest(run_dir, "COMPLETE" if (not pilot and validated == expected_rows == 240)
                      else "PARTIAL", {
        "measured": sum(r["status"] == "MEASURED" for r in data),
        "failed": sum(r["status"] == "FAILED" for r in data),
        "validated": validated,
        "environment": environment,
        "affinity": affinity,
        "validation_rule": "measured, negotiated suite == requested, captured record sizes within "
                           "RFC limit and >=95% of bytes in >=16000-byte records, cool-down gate "
                           "met and zero thermal-throttle events, affinity confined if pinning requested",
    })
    return run_dir


def validation_failures(row: dict, *, pilot: bool, pinning_requested: bool) -> list[str]:
    reasons = []
    if pilot:
        reasons.append("pilot run")
    if row.get("status") != "MEASURED":
        return reasons + ["not measured"]
    if not row.get("suite_verified"):
        reasons.append("negotiated suite differs from condition")
    if not row.get("record_size_ok"):
        reasons.append("record-size capture check failed")
    if not row.get("thermal_ok"):
        reasons.append("thermal: " + (row.get("thermal_reason") or "not recorded"))
    if pinning_requested and not row.get("server_affinity_verified"):
        reasons.append("server affinity not confined")
    return reasons


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--blocks", type=int)
    parser.add_argument("--tune-cpu", action="store_true")
    args = parser.parse_args()
    print(execute(pilot=args.pilot, blocks=args.blocks, tune_cpu=args.tune_cpu))


if __name__ == "__main__":
    main()
