"""E1: run PR01–PR22 across P1/P2/B1/B2/B3/A1/A2/A3, three repetitions."""
from contextlib import contextmanager
import argparse
import json
import os
import socket
import shutil
import sys
from pathlib import Path
import subprocess
import time

import yaml

from .evidence import new_run, append_jsonl, to_parquet, complete_manifest
from .experiment_control import await_tcp, ephemeral_server_profile, running_server
from .experiment_matrix import plan
from .launch import ROOT
from .probe_suite import probe_catalogue, run_probe, security_score


@contextmanager
def local_ocsp(log: Path):
    """Keep a private, loopback-only OCSP responder alive during E1."""
    with socket.socket() as check:
        if check.connect_ex(("127.0.0.1", 8888)) == 0:
            raise RuntimeError(
                "OCSP port 8888 already occupied; stop the old responder to prevent mixed-run evidence")
    log.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["TLSLAB_PYTHON"] = sys.executable
    env["TLSLAB_OCSP_BIND"] = "127.0.0.1"
    with log.open("w") as output:
        proc = subprocess.Popen(["bash", "pki/start_ocsp.sh"], cwd=ROOT,
                                env=env, stdout=output, stderr=subprocess.STDOUT)
        try:
            await_tcp("127.0.0.1", 8888, proc, timeout=12)
            yield
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


@contextmanager
def nginx_b3(log: Path, fuzz_dir: Path | None = None):
    """Run the B3 reference only after checking ports and nginx configuration."""
    nginx = shutil.which("nginx")
    if nginx is None:
        raise RuntimeError("B3 nginx executable not found in PATH")
    # Reject stale listeners just as running_server() does for Java profiles.
    for port in (8443, 8080):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.3)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise RuntimeError(
                    f"Refusing contaminated B3 experiment: 127.0.0.1:{port} already listening")
    prepare = subprocess.run(
        [sys.executable, "scripts/nginx_b3.py", "prepare",
         *(["--fuzz-cert-dir", str(fuzz_dir)] if fuzz_dir else [])],
        cwd=ROOT, capture_output=True, text=True, check=False)
    if prepare.returncode:
        raise RuntimeError(
            "B3 config preparation failed: " + prepare.stderr[-1200:])
    conf = prepare.stdout.strip()
    # A failed nginx -t produces actionable diagnostics; a bare
    # "server exited 1" loses the error and wastes all B3 repetitions.
    check = subprocess.run(
        [nginx, "-p", str(ROOT)+"/", "-c", conf, "-t"],
        cwd=ROOT, capture_output=True, text=True, check=False)
    if check.returncode:
        raise RuntimeError(
            f"B3 nginx configuration test exited {check.returncode}: "
            + (check.stderr + "\n" + check.stdout)[-1500:])
    cmd = [nginx, "-p", str(ROOT)+"/", "-c", conf, "-g", "daemon off;"]
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as stream:
        proc = subprocess.Popen(cmd, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
        try:
            try:
                await_tcp("127.0.0.1", 8443, proc)
            except (RuntimeError, TimeoutError) as exc:
                detail = log.read_text(errors="replace")[-1200:]
                raise RuntimeError(
                    f"B3 nginx failed to become ready: {exc}; startup log: {detail}") from exc
            yield proc
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def verify_base_keystore(path: Path) -> None:
    """Verify the existing lab PKCS#12 before creating a new E1 run.

    The RSA fuzz credential must be merged into this existing keystore.
    A fresh KS_PASS only encrypts the disposable RSA file; it cannot unlock
    the pre-existing lab credential made by `make pki`.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Missing lab keystore {path}; generate PKI before E1")
    try:
        check = subprocess.run(
            ["keytool", "-list", "-keystore", str(path), "-storetype", "PKCS12",
             "-storepass:env", "KS_PASS"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"Cannot verify existing lab keystore ({type(exc).__name__}); "
            "check keytool and JAVA_HOME"
        ) from exc
    if check.returncode != 0:
        # keytool can echo arbitrary environment strings in diagnostics.
        # Never print the keystore password or pass it as an argv literal.
        password = os.environ.get("KS_PASS", "")
        detail = check.stderr.strip()[-500:]
        if password:
            detail = detail.replace(password, "[REDACTED]")
        raise RuntimeError(
            "Cannot unlock existing pki/out/srv_plain.p12 using KS_PASS. "
            "Use the original password from `make pki` (do not regenerate "
            "the PKI or share the password). Keytool says: " + detail
        )


def fuzz_keystore(folder: Path) -> Path:
    """Lab server keystore plus a disposable all-RSA chain for the same name.

    Stock tlsfuzzer conversations (KeyUpdate, version negotiation) offer only
    RSA signature schemes in signature_algorithms and signature_algorithms_cert.
    The lab certificate is ECDSA P-256 under an ECDSA root, so the server has no
    credential it may present and every tlsfuzzer "sanity" handshake dies with
    handshake_failure. JSSE picks the entry by the client's schemes: ECDSA
    clients (OpenSSL, Java, curl, Python) still get the real lab certificate
    and its OCSP staple; RSA-only tlsfuzzer clients get this throwaway chain.
    """
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    env = os.environ.copy()
    def run(*argv):
        # Report keystore-import errors without displaying the password.
        proc = subprocess.run(argv, cwd=folder, env=env, check=False,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                              text=True)
        if proc.returncode:
            detail = proc.stderr.strip()[-650:]
            password = env.get("KS_PASS", "")
            if password:
                detail = detail.replace(password, "[REDACTED]")
            raise RuntimeError(
                f"E1 certificate preparation failed at {argv[0]} "
                f"(exit {proc.returncode}): {detail}"
            )
    run("openssl", "req", "-x509", "-newkey", "rsa:3072", "-noenc", "-days", "7",
        "-keyout", "rsa-ca.key", "-out", "rsa-ca.crt", "-subj", "/CN=TLS13-Lab E1 RSA Fuzz CA",
        "-addext", "basicConstraints=critical,CA:true,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign")
    run("openssl", "req", "-new", "-newkey", "rsa:2048", "-noenc",
        "-keyout", "rsa.key", "-out", "rsa.csr", "-subj", "/CN=lab.test")
    (folder/"leaf.cnf").write_text(
        "basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:lab.test,DNS:localhost,IP:127.0.0.1\n")
    run("openssl", "x509", "-req", "-in", "rsa.csr", "-CA", "rsa-ca.crt", "-CAkey", "rsa-ca.key",
        "-CAcreateserial", "-days", "7", "-sha256", "-extfile", "leaf.cnf", "-out", "rsa.crt")
    run("openssl", "pkcs12", "-export", "-inkey", "rsa.key", "-in", "rsa.crt",
        "-certfile", "rsa-ca.crt", "-name", "e1-rsa-fuzz", "-out", "rsa.p12",
        "-passout", "env:KS_PASS")
    target = folder/"srv_e1.p12"
    target.write_bytes((ROOT/"pki/out/srv_plain.p12").read_bytes())
    os.chmod(target, 0o600)
    run("keytool", "-importkeystore", "-noprompt",
        "-srckeystore", "rsa.p12", "-srcstoretype", "PKCS12", "-srcstorepass:env", "KS_PASS",
        "-destkeystore", str(target), "-deststoretype", "PKCS12", "-deststorepass:env", "KS_PASS")
    return target


def select_catalogue(catalogue: list[dict], probe_ids: str | None) -> list[dict]:
    """Select a reproducible subset of E1 probes for bounded integration tests."""
    if probe_ids is None:
        return catalogue
    requested = [v.strip() for v in probe_ids.split(",") if v.strip()]
    known = {item["id"] for item in catalogue}
    if not requested or len(requested) != len(set(requested)) or set(requested) - known:
        raise ValueError("Unknown, repeated or empty E1 probe identifier")
    return [item for item in catalogue if item["id"] in set(requested)]


def select_configurations(configs: list[dict], names: str | None) -> list[dict]:
    """Select profiles without changing experiment-matrix order or repetitions."""
    if names is None:
        return configs
    requested = [part.strip() for part in names.split(",")]
    known = {item["configuration"] for item in configs}
    if (not requested or any(not name for name in requested)
            or len(requested) != len(set(requested))
            or set(requested) - known):
        raise ValueError("Unknown, repeated or empty E1 configuration")
    return [item for item in configs if item["configuration"] in requested]


def execute(*, pilot: bool = False, probe_ids: str | None = None,
            configurations: str | None = None):
    if not os.getenv("KS_PASS"):
        raise ValueError("KS_PASS missing; run make pki and export password")
    if not (ROOT/"pki/out/ca.crt").is_file():
        raise FileNotFoundError("make pki first")
    # Fail before creating another INCOMPLETE run when the original
    # keystore password is missing or has changed between sessions.
    verify_base_keystore(ROOT/"pki/out/srv_plain.p12")
    configs = plan("E1")
    if pilot:
        configs = [c for c in configs if c["configuration"]=="P1" and c["repetition"]==1]
    configs = select_configurations(configs, configurations)
    if not configs:
        raise ValueError("Selected E1 configurations contain no planned cells")
    catalogue = select_catalogue(probe_catalogue(), probe_ids)
    selected_names = list(dict.fromkeys(c["configuration"] for c in configs))
    run = new_run("E1", {
        "pilot": pilot, "probe_ids": probe_ids or "PR01-PR22",
        "configurations": " ".join(selected_names),
        "repetitions": sorted({c["repetition"] for c in configs}),
    })
    rows = []
    keystore = fuzz_keystore(run/"e1-pki")
    with local_ocsp(run/"logs/ocsp.log"):
        for i, item in enumerate(configs):
            name = item["configuration"]
            completed_probes: set[str] = set()
            path = ROOT/"configs/server"/f"{name}.yaml"
            configuration = (
                {"provider":"OpenSSL","bindHost":"127.0.0.1","httpsPort":8443,
                 "httpPort":8080,"protocols":["TLSv1.3"],"hsts":True,
                 "httpRedirect":True,"ocspStapling":True,
                 "cipherSuites":[],"namedGroups":[]}
                if name == "B3" else yaml.safe_load(path.read_text()))
            try:
                if name == "B3":
                    ctx = nginx_b3(run/"logs"/f"B3_{i}.log", fuzz_dir=keystore.parent)
                    # nginx writes requests to its own access log (see template).
                    server_log = ROOT/"data/runtime/nginx-b3-access.log"
                    server_log.parent.mkdir(parents=True, exist_ok=True)
                    server_log.touch()
                else:
                    # Same profile, plus E1-only instrumentation: request log as
                    # server-side evidence and the RSA fuzz credential.
                    changes = {"accessLog": True, "keyStore": str(keystore)}
                    ecdsa = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                    if ecdsa in configuration.get("cipherSuites", []):
                        # RSA twin of the allowed TLS 1.2 suite, usable only by
                        # the RSA-only tlsfuzzer client (see fuzz_keystore).
                        changes["cipherSuites"] = [*configuration["cipherSuites"],
                                                   ecdsa.replace("ECDSA", "RSA")]
                    profile = ephemeral_server_profile(name, changes, run/"profiles"/f"{i}")
                    # launch.py derives the security policy from the file stem.
                    path = profile.with_name(f"{name}.yaml")
                    profile.rename(path)
                    server_log = run/"logs"/f"{name}_{i}.log"
                    ctx = running_server(path, server_log)
                with ctx:
                    for entry in catalogue:
                        try:
                            status = run_probe(entry, configuration,
                                               ca_file=ROOT/"pki/out/ca.crt",
                                               server_log=server_log)
                        except Exception as exc:
                            status = {"status":"INCONCLUSIVE", "observed":
                                      type(exc).__name__ + ": " + str(exc)[:300]}
                        row = {"experiment":"E1", **item, "probe_id":entry["id"],
                               "category":entry["category"], "outcome":status["status"],
                               "secure_outcome": security_score(
                                   entry["runner"], configuration, status["status"]),
                               "validated":status["status"] in ("PASS","FAIL","N/A")}
                        append_jsonl(run/"raw_evidence.jsonl", {
                            "row":row,"observation":status["observed"],
                            "details":status.get("evidence", {})})
                        rows.append(row)
                        completed_probes.add(entry["id"])
            except Exception as exc:
                # A process can die partway through a configuration. Preserve
                # earlier probe outcomes and mark only the *remaining* cells
                # BLOCKED; duplicate factor keys would invalidate the matrix.
                reason = type(exc).__name__ + ": " + str(exc)[:700]
                for entry in catalogue:
                    if entry["id"] in completed_probes:
                        continue
                    blocked = {"experiment":"E1", **item, "probe_id":entry["id"],
                               "category":entry["category"], "outcome":"BLOCKED",
                               "secure_outcome":None, "validated":False,
                               "error":reason}
                    append_jsonl(run/"raw_evidence.jsonl", {
                        "row":blocked, "observation":reason,
                        "details":{"phase":"server_setup_or_execution"}})
                    rows.append(blocked)
    to_parquet(rows, run/"results.parquet")
    counts = {s:sum(row["outcome"]==s for row in rows)
              for s in ("PASS","FAIL","BLOCKED","INCONCLUSIVE","N/A")}
    complete_manifest(run, "COMPLETE" if counts["BLOCKED"]==0 and counts["INCONCLUSIVE"]==0
                      else "PARTIAL", {"counts":counts,"cells":len(rows)})
    return run


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--pilot", action="store_true")
    args=parser.parse_args()
    print(execute(pilot=args.pilot))


if __name__ == "__main__":
    main()
