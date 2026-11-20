"""E7 controlled OCSP-stapling latency (off/warm/cold x RTT 0/50ms).

For real responder latency, start with --isolated as root: distinct SRV, CLI
and OCSP namespaces and netem are used. No Java agent or packet capture
runs in timed measurements. Evidence is labeled partial until audited.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import statistics
import numpy as np
import subprocess
import sys
import time

import yaml

from .env import managed_host_tuning, experiment_affinity, ThermalWindow, require_jdk
from .evidence import new_run, append_jsonl, to_parquet, complete_manifest
from .experiment_matrix import plan
from .experiment_control import ephemeral_server_profile, running_server, run_java_csv
from .wire_capture import wire_proxy, handshake_summary, connections
from .launch import ROOT
from .netns import isolated_network, delay, exec_in


def start_ocsp(*, isolated: bool, log: Path, directory: Path | None = None):
    # The reference nginx certificate uses an isolated-run OCSP CertID and
    # routable AIA; default E7 still uses the immutable original lab PKI.
    cmd = (["bash", str(ROOT / "pki/start_ocsp.sh")] if directory is None
           else [sys.executable, "-m", "tlslab.ocsp_static", "--dir", str(directory),
                 "--freshness", "fresh", "--bind",
                 "10.77.2.2" if isolated else "127.0.0.1", "--port", "8888"])
    if isolated:
        cmd = exec_in("tlslab-ocsp", cmd)
    log.parent.mkdir(parents=True, exist_ok=True)
    output = log.open("w")
    environment = os.environ.copy()
    environment["TLSLAB_PYTHON"] = sys.executable
    environment["TLSLAB_OCSP_BIND"] = "10.77.2.2" if isolated else "127.0.0.1"
    p = None
    try:
        p = subprocess.Popen(cmd, cwd=ROOT, env=environment,
                             stdout=output, stderr=subprocess.STDOUT)
        # A fixed sleep does not establish readiness, particularly when the
        # responder imports cryptography in a fresh isolated namespace.
        deadline = time.monotonic() + 12
        target = "10.77.2.2" if isolated else "127.0.0.1"
        while time.monotonic() < deadline:
            if p.poll() is not None:
                raise RuntimeError("OCSP responder exited; see " + str(log))
            check = [sys.executable, "-c",
                     "import socket; socket.create_connection((" +
                     repr(target) + ",8888),1).close()"]
            if isolated:
                check = exec_in("tlslab-ocsp", check)
            if subprocess.run(check, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=3).returncode == 0:
                return p, output
            time.sleep(0.1)
        raise TimeoutError("OCSP responder readiness timeout; see " + str(log))
    except BaseException:
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        output.close()
        raise


def stop_process(process, logfile):
    try:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    finally:
        logfile.close()


WARMUP_PORTS = (8444, 8081)   # auxiliary stapling-off server for client JVM warm-up


def warmup_counts(pilot: bool) -> tuple[int, int]:
    """(client JVM warm-up handshakes, server JVM warm-up handshakes)."""
    return (20, 20) if pilot else (200, 200)


def handshake_batch(n, *, isolated: bool, host: str, client_affinity=None,
                    client_warmup: int = 0, status_request: bool = True):
    cmd = ["127.0.0.1" if not isolated else host, "8443",
           "lab.test", "SunJSSE", "x25519", str(n),
           str(ROOT / "pki/out/truststore.p12")]
    env = {"TLSLAB_WARMUP_TARGET": f"{host}:{WARMUP_PORTS[0]}:{client_warmup}"} if client_warmup else None
    # Without status_request the server never fetches OCSP, so warming the
    # server JVM this way leaves its OCSP cache cold (verified on JDK 27).
    jvm = None if status_request else ["-Djdk.tls.client.enableStatusRequestExtension=false"]
    rows = run_java_csv("HandshakeClient", cmd,
                        timeout=max(90, (n + client_warmup)*2),
                        namespace="tlslab-cli" if isolated else None,
                        client_affinity=client_affinity, jvm_args=jvm, env=env)
    if len(rows) != n or any(row["status"] != "OK" for row in rows):
        raise RuntimeError("failed handshake(s) in E7 batch")
    timings = [int(row["handshake_ns"])/1e6 for row in rows if int(row["handshake_ns"]) > 0]
    if len(timings) != n:
        raise RuntimeError("missing E7 handshake timings")
    return timings


def require_lab_truststore_password() -> None:
    """Verify existing PKCS12 truststore before allocating an E7 run.

    keytool reads KS_PASS from the environment, NOT a command-line
    argument. No password is printed or recorded. Never regenerate the
    truststore or PKI to make this preflight succeed.
    """
    if not os.environ.get("KS_PASS"):
        raise EnvironmentError("KS_PASS required (use the password from original make pki)")
    truststore = ROOT / "pki/out/truststore.p12"
    if not truststore.is_file():
        raise FileNotFoundError("Missing pki/out/truststore.p12; lab PKI not built")
    try:
        check = subprocess.run([
            "keytool", "-list", "-storetype", "PKCS12",
            "-keystore", str(truststore), "-storepass:env", "KS_PASS",
        ], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
           text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            "Could not verify E7 truststore using JDK keytool; "
            "check JAVA_HOME and PATH before running E7") from exc
    if check.returncode != 0:
        raise ValueError(
            "KS_PASS cannot open existing pki/out/truststore.p12. "
            "Use the original make pki password, verify with "
            "'keytool -list -storetype PKCS12 -keystore "
            "pki/out/truststore.p12 -storepass:env KS_PASS', "
            "and do not delete or regenerate existing PKI.")


def thermally_monitored_batch(n, *, isolated: bool, host: str,
                              client_affinity=None, client_warmup: int = 0):
    """Capture throttle counters ONLY around the timed client's batch.

    A fresh gate runs after separate server startup/cache priming. The same
    JVM's untimed client warm-up (if any) remains within the counter window:
    it can heat the CPU immediately before the first measured handshake, so
    including it is conservative. OCSP follow-up checks and wire proxies
    must not invalidate a latency sample due to unrelated later throttling.
    """
    thermal = ThermalWindow()
    try:
        timings = handshake_batch(n, isolated=isolated, host=host,
                                  client_affinity=client_affinity,
                                  client_warmup=client_warmup)
    finally:
        outcome = thermal.close()
    return timings, outcome


def combine_thermal_windows(windows: list[dict]) -> dict:
    """Preserve every measurement window (two for a cold pilot restart)."""
    if not windows:
        raise ValueError("No measurement thermal windows available")
    counts = [w.get("throttle_events") for w in windows]
    return {
        "ok": all(w.get("ok") is True for w in windows),
        "throttle_events": sum(counts) if all(n is not None for n in counts) else None,
        "reasons": [f"window {i}: {reason}" for i, w in enumerate(windows, 1)
                    for reason in w.get("reasons", [])],
        "gate": [w.get("gate") for w in windows],
    }


def check_staple(*, isolated: bool, host: str):
    cmd = ["openssl", "s_client", "-tls1_3", "-status",
           "-connect", f"{host}:8443", "-servername", "lab.test",
           "-CAfile", str(ROOT/"pki/out/ca.crt")]
    if isolated:
        cmd = exec_in("tlslab-cli", cmd)
    p = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=12)
    output = p.stdout + p.stderr
    return ("OCSP Response Status: successful" in output
            and "Cert Status: good" in output
            and "Next Update:" in output)


def execute(*, pilot: bool, isolated: bool, allow_host_tuning: bool):
    if not os.getenv("KS_PASS"):
        raise ValueError("KS_PASS required")
    if not (ROOT/"pki/out/ca.crt").is_file():
        raise FileNotFoundError("make pki first")
    if not (ROOT/"java/target/tlslab-server.jar").is_file():
        raise FileNotFoundError("make build first")
    require_lab_truststore_password()
    if not isolated and not pilot:
        raise ValueError("Full E7 needs --isolated for 50ms responder RTT and independent OCSP network")
    affinity = experiment_affinity()
    rows = plan("E7", blocks=1 if pilot else None)
    if pilot and not isolated:
        rows = [r for r in rows if r["rtt_ms"] == 0]
    out = new_run("E7", {"pilot":pilot, "isolated":isolated,
                         "warm_off_batch": 3 if pilot else 500,
                         "cold_restarts_per_block": 2 if pilot else 1})
    measurements = []
    with ExitStack() as context:
        tuning = context.enter_context(managed_host_tuning(allow_host_tuning))
        if isolated:
            context.enter_context(isolated_network())
        responder, log = start_ocsp(isolated=isolated, log=out/"logs/ocsp.log")
        context.callback(stop_process, responder, log)
        jdk = require_jdk(27, "E7")
        warm_host = "10.77.1.1" if isolated else "127.0.0.1"
        warm_profile = ephemeral_server_profile("A1", {
            "bindHost": warm_host, "httpsPort": WARMUP_PORTS[0], "httpPort": WARMUP_PORTS[1],
            "namedGroups": ["x25519"], "ocspStapling": False,
        }, out/"profiles"/"client-warmup")
        context.enter_context(running_server(
            warm_profile, out/"logs"/"client-warmup-server.log",
            namespace="tlslab-srv" if isolated else None))
        for index, cond in enumerate(rows):
            rtt = cond["rtt_ms"]
            phase = cond["stapling"]
            if isolated:
                delay(rtt, ocsp=True)
                delay(0, ocsp=False)
            host = "10.77.1.1" if isolated else "127.0.0.1"
            base = "A1" if phase == "off" else "P1"
            profile = ephemeral_server_profile(base, {
                "bindHost": host, "namedGroups": ["x25519"],
                "ocspStapling": phase != "off",
                "ocspResponderUri": "http://10.77.2.2:8888" if isolated
                                    else "http://127.0.0.1:8888",
            }, out/"profiles"/f"{index}")
            evidence = {**cond, "condition": phase, "status": "INCOMPLETE",
                        "validated": False, "n_handshakes": 0}
            timings = []
            try:
                count = (2 if pilot else 1) if phase == "cold" else 1
                client_warm, server_warm = warmup_counts(pilot)
                thermal_windows = []
                for restart in range(count):
                    with running_server(profile, out/"logs"/f"{index}-{restart}.log",
                                        namespace="tlslab-srv" if isolated else None,
                                        server_affinity=affinity["server"]):
                        # Identical in every condition: warm the server JVM with
                        # handshakes that do not request a staple (cache stays cold).
                        handshake_batch(server_warm, isolated=isolated, host=host,
                                        client_affinity=affinity["client"], status_request=False)
                        if phase == "warm":
                            # Prime cache; keep this handshake out of timing.
                            handshake_batch(1, isolated=isolated, host=host, client_affinity=affinity["client"])
                        if phase == "warm" and not check_staple(isolated=isolated, host=host):
                            raise RuntimeError("No valid OCSP staple in warm condition")
                        n = (3 if pilot else 500) if phase != "cold" else 1
                        # The first handshake after each cold restart MUST be timed
                        # before any separate -status probe. Otherwise the probe
                        # itself warms the server OCSP cache and destroys E7's IV.
                        # The client JVM first warms up against the auxiliary
                        # stapling-off server, so JVM start-up cost is excluded.
                        samples, measurement_window = thermally_monitored_batch(
                            n, isolated=isolated, host=host,
                            client_affinity=affinity["client"],
                            client_warmup=client_warm)
                        timings.extend(samples)
                        thermal_windows.append(measurement_window)
                        if phase == "cold" and not check_staple(isolated=isolated, host=host):
                            raise RuntimeError("No valid OCSP staple after cold timing")
                        if phase == "off" and check_staple(isolated=isolated, host=host):
                            raise RuntimeError("Staple present although stapling is off")
                        if restart == count - 1:
                            # Untimed captured sample: same client settings, must be
                            # full TLS 1.3 handshakes with no PSK/resumption.
                            wire_dir = out/"wire"/str(index)
                            with wire_proxy(host, 8443, wire_dir,
                                            namespace="tlslab-cli" if isolated else None) as (ph, pp):
                                run_java_csv("HandshakeClient", [ph, str(pp), "lab.test", "SunJSSE",
                                             "x25519", "3", str(ROOT/"pki/out/truststore.p12")],
                                             timeout=90, namespace="tlslab-cli" if isolated else None)
                            sample = [handshake_summary(c) for c in connections(wire_dir)]
                            full_handshakes = len(sample) == 3 and all(
                                h["tls13"] and not h["psk_offered"] and not h["psk_accepted"]
                                and not h["hrr"] for h in sample)
                window = combine_thermal_windows(thermal_windows)
                if phase == "cold" and len(timings) != count:
                    raise RuntimeError("incomplete cold batch")
                if phase != "cold" and len(timings) != (3 if pilot else 500):
                    raise RuntimeError("incomplete warm/off batch")
                evidence.update({
                    "status": "MEASURED",
                    "handshake_ms": statistics.median(timings),
                    "handshake_p95_ms": float(np.percentile(timings, 95)),
                    "n_handshakes": len(timings),
                    "staple_state_verified": True,   # checks above raise otherwise
                    "full_handshake_verified": full_handshakes,
                    "client_warmup_handshakes": client_warm,
                    "server_warmup_handshakes": server_warm,
                    "thermal_ok": window["ok"],
                    "thermal_reason": "; ".join(window["reasons"]) or None,
                    "throttle_events": window["throttle_events"],
                    "thermal_window_scope":
                        "timed client batch + same-process untimed client warm-up",
                    "thermal_gates": json.dumps(window["gate"], sort_keys=True),
                })
            except Exception as exc:
                evidence.update({"status": "FAILED",
                                 "error": type(exc).__name__ + ": " + str(exc)[:500]})
            for value in timings:
                append_jsonl(out/"raw_handshakes.jsonl",
                             {"block":cond["block"], "stapling":phase, "rtt_ms":rtt,
                              "handshake_ms":value})
            append_jsonl(out/"measurements.jsonl", evidence)
            measurements.append(evidence)
    for row in measurements:
        reasons = validation_failures(row, pilot=pilot, isolated=isolated, jdk=jdk)
        row["validated"] = not reasons
        row["validation_failures"] = "; ".join(reasons) or None
    to_parquet(measurements, out/"results.parquet")
    validated = sum(bool(r["validated"]) for r in measurements)
    complete_manifest(out, "PARTIAL", {"total_conditions":len(rows),
                                      "measured":sum(r["status"]=="MEASURED" for r in measurements),
                                      "failed":sum(r["status"]=="FAILED" for r in measurements),
                                      "validated":validated,
                                      # Rows can be individually valid, but the study
                                      # design also requires the nginx/OpenSSL B3
                                      # reference, which is not implemented yet.
                                      "b3_reference": "SEPARATE INDEPENDENT REFERENCE REQUIRED FOR FINAL AUDIT",
                                      "validation_rule": "isolated, JDK>=27, measured, staple state "
                                          "verified, captured full handshakes, client+server JVM warm-up, "
                                          "cool-down gate met and zero thermal-throttle events",
                                      "affinity":affinity,
                                      "cpu_tuning": {
                                          "requested":bool(allow_host_tuning),
                                          "tuned":bool(tuning.get("tuned")),
                                          "effective_controls":tuning.get("post", tuning.get("pre")),
                                      }})
    return out


def validation_failures(row: dict, *, pilot: bool, isolated: bool, jdk: int) -> list[str]:
    reasons = []
    if pilot:
        reasons.append("pilot run")
    if not isolated:
        reasons.append("not isolated (no controlled responder RTT)")
    if jdk < 27:
        reasons.append(f"JDK {jdk} < 27")
    if row.get("status") != "MEASURED":
        return reasons + ["not measured"]
    if not row.get("full_handshake_verified"):
        reasons.append("captured sample not all full TLS 1.3 handshakes")
    if not row.get("thermal_ok"):
        reasons.append("thermal: " + (row.get("thermal_reason") or "not recorded"))
    return reasons


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--isolated", action="store_true")
    parser.add_argument("--tune-cpu", action="store_true")
    args = parser.parse_args()
    print(execute(pilot=args.pilot, isolated=args.isolated,
                  allow_host_tuning=args.tune_cpu))


if __name__ == "__main__":
    main()
