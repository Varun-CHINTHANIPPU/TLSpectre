"""Independent B3/nginx/OpenSSL reference for the E7 stapling-latency matrix.

This is intentionally a separate data collection, NOT a silent addition to the
Java E7 observations. It uses the same TLS 1.3 Java handshake timer/client,
block order, responder RTT and PKI trust anchor, but a *different* TLS server.

The original E7 measurements remain immutable under data/raw/E7.
Reference runs are written to data/references/E7. No reference measurement
is claimed until the user actually executes this runner on the target host.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import secrets
import shutil
import statistics
import subprocess
import sys
import time

import numpy as np

from .env import experiment_affinity, managed_host_tuning, require_jdk
from .evidence import append_jsonl, complete_manifest, new_run, to_parquet
from .experiment_control import ephemeral_server_profile, running_server, run_java_csv
from .experiment_matrix import plan
from .launch import ROOT
from .netns import delay, exec_in, isolated_network
from .probe_suite import classify_staple
from .run_e7 import (WARMUP_PORTS, handshake_batch, start_ocsp, stop_process,
                     warmup_counts, thermally_monitored_batch,
                     combine_thermal_windows, require_lab_truststore_password)
from .wire_capture import wire_proxy, handshake_summary, connections


def _openssl(*args: str):
    p = subprocess.run(["openssl", *map(str, args)], cwd=ROOT, capture_output=True,
                       text=True, timeout=40)
    if p.returncode:
        raise RuntimeError("OpenSSL reference credential generation failed: " + p.stderr[-900:])


def reference_credential(directory: Path, *, isolated: bool) -> tuple[Path, Path]:
    """Create a unique short-lived ECDSA cert with OCSP AIA reachable by nginx.

    In netns mode the usual lab AIA (127.0.0.1) refers to nginx's own
    namespace, not the dedicated 10.77.2.2 responder namespace. Generate a
    disposable replacement signed by the SAME lab CA and served by a fresh
    request-matched OCSP responder. No global PKI database is modified.
    """
    directory.mkdir(parents=True, exist_ok=False)
    directory.chmod(0o700)
    source = ROOT / "pki" / "out"
    uri = "http://10.77.2.2:8888" if isolated else "http://127.0.0.1:8888"
    ext = directory / "cert.ext"
    ext.write_text(
        "basicConstraints=critical,CA:false\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:lab.test,DNS:localhost,IP:127.0.0.1,IP:10.77.1.1\n"
        f"authorityInfoAccess=OCSP;URI:{uri}\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n")
    key = directory / "srv_plain.key"
    csr = directory / "srv_plain.csr"
    cert = directory / "srv_plain.crt"
    _openssl("req", "-new", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:P-256", "-noenc", "-keyout", str(key),
             "-out", str(csr), "-subj", "/CN=lab.test")
    _openssl("x509", "-req", "-in", str(csr), "-CA", str(source/"ca.crt"),
             "-CAkey", str(source/"ca.key"), "-set_serial",
             str(secrets.randbits(96) | (1 << 95)), "-days", "3",
             "-sha256", "-extfile", str(ext), "-out", str(cert))
    cert.chmod(0o600)
    key.chmod(0o600)
    for name in ("ca.crt", "ocsp.crt", "ocsp.key"):
        destination = directory / name
        shutil.copyfile(source / name, destination)
        destination.chmod(0o600)
    from cryptography import x509
    parsed = x509.load_pem_x509_certificate(cert.read_bytes())
    (directory/"serial-map.json").write_text(json.dumps(
        {str(parsed.serial_number): "srv_plain"}) + "\n")
    return cert, key


def reference_nginx_config(folder: Path, *, cert: Path, key: Path,
                           isolated: bool, stapling: str) -> Path:
    """Create a per-condition nginx config with isolated, non-global paths."""
    if stapling not in {"off", "warm", "cold"}:
        raise ValueError("invalid E7 stapling mode")
    folder.mkdir(parents=True, exist_ok=True)
    template = (ROOT/"conf/nginx-b3.conf.template").read_text()
    required = [
        "        @@FUZZ_CERT@@", "listen 127.0.0.1:8443 ssl;",
        "listen 127.0.0.1:8080;", "ssl_stapling on;",
        "ssl_stapling_verify on;", "ssl_session_cache off;",
        "ssl_certificate @@ROOT@@/pki/out/srv_plain.crt;",
        "ssl_certificate_key @@ROOT@@/pki/out/srv_plain.key;",
        "pid @@ROOT@@/data/runtime/nginx-b3.pid;",
        "error_log @@ROOT@@/data/runtime/nginx-b3-error.log warn;",
        "access_log @@ROOT@@/data/runtime/nginx-b3-access.log;",
    ]
    if any(template.count(token) != 1 for token in required):
        raise ValueError("B3 reference template changed; audit substitutions first")
    host = "10.77.1.1" if isolated else "127.0.0.1"
    replacements = {
        "        @@FUZZ_CERT@@": "",
        "listen 127.0.0.1:8443 ssl;": f"listen {host}:8443 ssl;",
        "listen 127.0.0.1:8080;": f"listen {host}:8080;",
        "ssl_stapling on;": "ssl_stapling on;" if stapling != "off" else "ssl_stapling off;",
        "ssl_stapling_verify on;": ("ssl_stapling_verify on;" if stapling != "off"
                                     else "ssl_stapling_verify off;"),
        "ssl_session_cache off;": "ssl_session_cache off;\n    ssl_session_tickets off;",
        "ssl_certificate @@ROOT@@/pki/out/srv_plain.crt;": f"ssl_certificate {cert};",
        "ssl_certificate_key @@ROOT@@/pki/out/srv_plain.key;": f"ssl_certificate_key {key};",
        "pid @@ROOT@@/data/runtime/nginx-b3.pid;": f"pid {folder/'nginx.pid'};",
        "error_log @@ROOT@@/data/runtime/nginx-b3-error.log warn;":
            f"error_log {folder/'nginx-error.log'} warn;",
        "access_log @@ROOT@@/data/runtime/nginx-b3-access.log;":
            f"access_log {folder/'nginx-access.log'};",
    }
    for old, new in replacements.items():
        template = template.replace(old, new)
    # All paths, including nginx temporary request-body paths, are inside the
    # local repository and never require writes to /etc/nginx or /var/lib/nginx.
    template = template.replace("@@ROOT@@", str(ROOT))
    if "@@" in template:
        raise ValueError("unexpanded nginx reference placeholder")
    for name in ("client-body", "proxy", "fastcgi", "uwsgi", "scgi"):
        (ROOT/"data/runtime/nginx-temp"/name).mkdir(parents=True, exist_ok=True)
    conf = folder/"nginx.conf"
    conf.write_text(template)
    return conf


@contextmanager
def nginx_reference_server(conf: Path, log: Path, *, isolated: bool):
    binary = shutil.which("nginx")
    if not binary:
        raise RuntimeError("nginx required for the E7 B3 independent reference")
    flags = [binary, "-p", str(ROOT)+"/", "-c", str(conf)]
    # nginx -t does more than syntax validation: it also checks listen()
    # bindings. In isolated E7, 10.77.1.1 only exists in tlslab-srv, not
    # the host network namespace. Validate in the same namespace used for
    # the actual nginx process, otherwise ALL 180 cells fail before timing.
    check_cmd = [*flags, "-t"]
    if isolated:
        check_cmd = exec_in("tlslab-srv", check_cmd)
    check = subprocess.run(check_cmd, capture_output=True, text=True,
                           timeout=20, cwd=ROOT)
    if check.returncode:
        raise RuntimeError("nginx reference configuration invalid: " + check.stderr[-1600:])
    cmd = [*flags, "-g", "daemon off;"]
    if isolated:
        cmd = exec_in("tlslab-srv", cmd)
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as sink:
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=sink, stderr=subprocess.STDOUT)
        try:
            host = "10.77.1.1" if isolated else "127.0.0.1"
            ready = [sys.executable, "-c",
                     f"import socket; socket.create_connection(({host!r},8443),1).close()"]
            if isolated:
                ready = exec_in("tlslab-srv", ready)
            for _ in range(150):
                if p.poll() is not None:
                    raise RuntimeError("nginx E7 reference exited: " +
                                       log.read_text(errors="replace")[-1500:])
                if subprocess.run(ready, capture_output=True, timeout=4).returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise TimeoutError("nginx reference endpoint not ready")
            yield p
        finally:
            if p.poll() is None:
                p.terminate()
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()


def observed_staple(*, host: str, isolated: bool) -> dict:
    cmd = ["openssl", "s_client", "-tls1_3", "-status", "-connect", f"{host}:8443",
           "-servername", "lab.test", "-CAfile", str(ROOT/"pki/out/ca.crt")]
    if isolated:
        cmd = exec_in("tlslab-cli", cmd)
    p = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=15)
    transcript = p.stdout + "\n" + p.stderr
    return {"state": classify_staple(transcript), "exit": p.returncode,
            "status_lines": [x.strip() for x in transcript.splitlines()
                             if ("OCSP " in x or "Cert Status:" in x
                                 or "Next Update:" in x)][:16]}


def await_good_staple(*, host: str, isolated: bool, attempts: int = 10) -> list[dict]:
    history = []
    for n in range(attempts):
        evidence = observed_staple(host=host, isolated=isolated)
        history.append(evidence)
        if evidence["state"] == "good" and evidence["exit"] == 0:
            return history
        if evidence["state"] != "missing":
            raise RuntimeError("Unusable OCSP response in nginx E7 reference: " +
                               repr(evidence))
        if n + 1 < attempts:
            time.sleep(0.4)
    raise RuntimeError("No OCSP staple after warm-up: " + repr(history))


def execute(*, pilot: bool, isolated: bool, allow_host_tuning: bool):
    if not os.environ.get("KS_PASS"):
        raise EnvironmentError("KS_PASS required")
    if not (ROOT/"pki/out/ca.key").is_file():
        raise FileNotFoundError("make pki first (reference requires signing an ephemeral leaf)")
    if not (ROOT/"java/target/tlslab-server.jar").is_file():
        raise FileNotFoundError("make build first")
    if not shutil.which("nginx"):
        raise RuntimeError("E7 B3 reference requires nginx")
    require_lab_truststore_password()
    if not pilot and not isolated:
        raise ValueError("Full E7 B3 reference requires isolated namespace/OCSP RTT")
    rows = plan("E7", blocks=1 if pilot else None)
    if pilot and not isolated:
        rows = [r for r in rows if r["rtt_ms"] == 0]
    reference = new_run("E7", {"pilot": pilot, "isolated": isolated,
                               "stack": "nginx/OpenSSL B3",
                               "reference_only": True,
                               "reference_pki_ephemeral": True},
                        collection="references")
    credential_dir = reference/"pki"
    cert, key = reference_credential(credential_dir, isolated=isolated)
    measurements = []
    affinity = experiment_affinity()
    with ExitStack() as ctx:
        tuning = ctx.enter_context(managed_host_tuning(allow_host_tuning))
        if isolated:
            ctx.enter_context(isolated_network())
        responder, log = start_ocsp(
            isolated=isolated, log=reference/"logs/ocsp.log", directory=credential_dir)
        ctx.callback(stop_process, responder, log)
        jdk = require_jdk(27, "E7 B3 reference")
        host = "10.77.1.1" if isolated else "127.0.0.1"
        warm_profile = ephemeral_server_profile("A1", {
            "bindHost": host, "httpsPort": WARMUP_PORTS[0],
            "httpPort": WARMUP_PORTS[1], "namedGroups": ["x25519"],
            "ocspStapling": False}, reference/"profiles/client-warmup")
        ctx.enter_context(running_server(
            warm_profile, reference/"logs/client-warmup.log",
            namespace="tlslab-srv" if isolated else None))
        for index, condition in enumerate(rows):
            mode = condition["stapling"]
            if isolated:
                delay(condition["rtt_ms"], ocsp=True)
                delay(0, ocsp=False)
            record = {**condition, "stack": "nginx/OpenSSL B3",
                      "status": "INCOMPLETE", "validated": False,
                      "n_handshakes": 0, "signature_verified_by_probe": False}
            timings = []
            try:
                client_warm, server_warm = warmup_counts(pilot)
                thermal_windows = []
                restarts = (2 if pilot else 1) if mode == "cold" else 1
                history = []
                for restart in range(restarts):
                    folder = reference/"nginx"/str(index)/str(restart)
                    conf = reference_nginx_config(folder, cert=cert, key=key,
                                                  isolated=isolated, stapling=mode)
                    with nginx_reference_server(
                            conf, reference/"logs"/f"nginx-{index}-{restart}.log",
                            isolated=isolated):
                        # No status_request while prewarming nginx, so the OCSP
                        # fetch is not triggered before the cold measurement.
                        handshake_batch(server_warm, isolated=isolated, host=host,
                                        status_request=False,
                                        client_affinity=affinity["client"])
                        if mode == "warm":
                            handshake_batch(1, isolated=isolated, host=host,
                                            client_affinity=affinity["client"])
                            history += await_good_staple(host=host, isolated=isolated)
                        n = (3 if pilot else 500) if mode != "cold" else 1
                        # COLD: timed first status_request occurs BEFORE any
                        # independent staple check against this nginx process.
                        samples, measurement_window = thermally_monitored_batch(
                            n, isolated=isolated, host=host,
                            client_affinity=affinity["client"],
                            client_warmup=client_warm)
                        timings.extend(samples)
                        thermal_windows.append(measurement_window)
                        if mode == "cold":
                            history += await_good_staple(host=host, isolated=isolated)
                        if mode == "off":
                            state = observed_staple(host=host, isolated=isolated)
                            history.append(state)
                            if state["state"] != "missing":
                                raise RuntimeError("OCSP status present when nginx stapling off")
                        if restart == restarts - 1:
                            wire_dir = reference/"wire"/str(index)
                            with wire_proxy(host, 8443, wire_dir,
                                            namespace="tlslab-cli" if isolated else None) as (h,p):
                                run_java_csv("HandshakeClient", [
                                    h, str(p), "lab.test", "SunJSSE", "x25519", "3",
                                    str(ROOT/"pki/out/truststore.p12")], timeout=90,
                                    namespace="tlslab-cli" if isolated else None)
                            summaries = [handshake_summary(c) for c in connections(wire_dir)]
                            full = len(summaries) == 3 and all(
                                s["tls13"] and not s["psk_offered"] and not
                                s["psk_accepted"] and not s["hrr"] for s in summaries)
                window = combine_thermal_windows(thermal_windows)
                expected = restarts if mode == "cold" else (3 if pilot else 500)
                if len(timings) != expected:
                    raise RuntimeError(f"Incomplete reference timing batch: {len(timings)}/{expected}")
                record.update({
                    "status": "MEASURED", "n_handshakes": len(timings),
                    "handshake_ms": statistics.median(timings),
                    "handshake_p95_ms": float(np.percentile(timings, 95)),
                    "full_handshake_verified": full,
                    "staple_state_verified": True,
                    "staple_history": json.dumps(history, sort_keys=True),
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
                record.update({"status": "FAILED",
                               "error": type(exc).__name__ + ": " + str(exc)[:1000]})
            for latency in timings:
                append_jsonl(reference/"raw_handshakes.jsonl", {
                    "stack": "nginx/OpenSSL B3", "block": condition["block"],
                    "stapling": mode, "rtt_ms": condition["rtt_ms"],
                    "handshake_ms": latency})
            append_jsonl(reference/"measurements.jsonl", record)
            measurements.append(record)
    for row in measurements:
        reasons = []
        if pilot:
            reasons.append("pilot only")
        if not isolated:
            reasons.append("no isolated responder RTT")
        if row["status"] != "MEASURED":
            reasons.append("not measured")
        else:
            if not row.get("full_handshake_verified"):
                reasons.append("full TLS 1.3 handshake control not confirmed")
            if not row.get("staple_state_verified"):
                reasons.append("OCSP field-level staple state not confirmed")
            if not row.get("thermal_ok"):
                reasons.append("thermal: " + str(row.get("thermal_reason")))
        row["validated"] = not reasons
        row["validation_failures"] = "; ".join(reasons) or None
    to_parquet(measurements, reference/"results.parquet")
    valid = sum(bool(r["validated"]) for r in measurements)
    complete = not pilot and len(rows) == len(measurements) == valid == 180
    complete_manifest(reference, "COMPLETE" if complete else "PARTIAL", {
        "rows": len(measurements), "validated": valid,
        "failed": sum(r["status"] == "FAILED" for r in measurements),
        "b3_reference": "MEASURED" if complete else "NOT VALIDATED",
        "verification_scope": "nginx B3; on-wire TLS group/no PSK and OCSP field "
                              "checks; independently signed OCSP response NOT verified by s_client",
        "frozen_conditions": "3 modes x 2 OCSP RTT x 30 blocks; independent reference",
        "cpu_tuning": {
            "requested": bool(allow_host_tuning),
            "tuned": bool(tuning.get("tuned")),
            "effective_controls": tuning.get("post", tuning.get("pre")),
        },
    })
    return reference
