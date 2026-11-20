"""Five E6 client policies from the source design; local laboratory only."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile

import sys
from .netns import exec_in
from .tool_wrappers import check_target
from .launch import ROOT


def k1_curl(host: str, port: int, ca: Path, timeout: int = 10):
    if shutil.which("curl") is None:
        return {"policy": "K1", "outcome": "BLOCKED", "reason": "curl missing"}
    cmd = ["curl", "--noproxy", "*", "--silent", "--show-error",
           "--cert-status", "--cacert", str(ca), "--connect-timeout", str(timeout),
           "--max-time", str(timeout + 5), "--resolve",
           f"lab.test:{port}:{host}", "-o", "/dev/null", "-w", "%{http_code}",
           f"https://lab.test:{port}/health"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 8)
    except subprocess.TimeoutExpired:
        return {"policy": "K1", "outcome": "BLOCKED", "reason": "curl timed out"}
    # Transport availability failures are not evidence of a secure rejection.
    if p.returncode in (5, 6, 7, 28, 52, 56):
        outcome = "BLOCKED"
    else:
        outcome = "ACCEPT" if p.returncode == 0 and p.stdout.strip() == "200" else "REJECT"
    return {"policy": "K1", "outcome": outcome,
            "returncode": p.returncode, "error": p.stderr[-300:]}


def java_policy(host: str, port: int, policy: str, truststore: Path, timeout=5000):
    if policy not in ("K2", "K3", "K4", "K6"):
        raise ValueError("invalid Java policy")
    jar = ROOT / "java/target/tlslab-server.jar"
    if not jar.is_file():
        return {"policy": policy, "outcome": "BLOCKED", "reason": "Java artifact missing"}
    if not os.getenv("KS_PASS"):
        return {"policy": policy, "outcome": "BLOCKED", "reason": "KS_PASS missing"}
    command = ["java", "-cp", str(jar),
               "lab.tls13.client.RevocationClient", host, str(port), "lab.test",
               policy, str(truststore), str(timeout)]
    try:
        p = subprocess.run(command, capture_output=True, text=True,
                           timeout=timeout / 1000 + 8)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"policy": policy, "outcome": "BLOCKED", "reason": type(exc).__name__}
    match = re.search(r"\bresult=(ACCEPT|REJECT|BLOCKED)\b", p.stdout)
    if not match:
        return {"policy": policy, "outcome": "BLOCKED", "reason":
                "Unparseable Java policy output: " + p.stderr[-200:]}
    return {"policy": policy, "outcome": match.group(1),
            "returncode": p.returncode, "observed": p.stdout[-400:]}


def k5_python_crl(host: str, port: int, ca: Path, crl: Path, timeout=10):
    if not crl.is_file() or not ca.is_file():
        return {"policy": "K5", "outcome": "BLOCKED", "reason": "CA/CRL missing"}
    # OpenSSL loads the trust anchor and CRL from one CAfile path.
    bundle = ca.read_bytes() + b"\n" + crl.read_bytes()
    with tempfile.TemporaryDirectory(prefix="tlslab-crl-") as directory:
        file = Path(directory) / "trust+crl.pem"
        file.write_bytes(bundle)
        context = ssl.create_default_context(cafile=str(file))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname="lab.test") as s:
                    s.settimeout(timeout)
                    s.sendall(b"HEAD /health HTTP/1.1\r\nHost: lab.test\r\nConnection: close\r\n\r\n")
                    start = s.recv(128)
                    if not start.startswith(b"HTTP/1.1 200"):
                        return {"policy": "K5", "outcome": "REJECT", "reason": "unexpected HTTP response"}
                    return {"policy": "K5", "outcome": "ACCEPT", "tls": s.version()}
        except ssl.SSLError as exc:
            return {"policy": "K5", "outcome": "REJECT",
                    "reason": type(exc).__name__ + ": " + str(exc)[:200]}
        except OSError as exc:
            return {"policy": "K5", "outcome": "BLOCKED",
                    "reason": type(exc).__name__ + ": " + str(exc)[:200]}


def expected_outcome(scenario: dict, policy: str) -> str:
    """What each client policy should do in an E6 scenario, from its definition.

    K1 curl --cert-status: needs a stapled, fresh, good response; never fetches.
    K2 JDK PKIX, OCSP hard-fail: stapled response first, else direct OCSP;
       anything undeterminable (unreachable, expired) is a rejection.
    K3 JDK PKIX, SOFT_FAIL: like K2, except a *network* failure to reach the
       responder is tolerated. An expired response is not a network failure.
    K4 JDK default trust manager: no revocation checking at all.
    K5 Python/OpenSSL with the CA's CRL: revoked iff listed in the CRL.

    The responder serves the same freshness as the staple, so an "expired"
    scenario gives expired data on both paths. Must-Staple is not enforced
    by any of the five policies (K6 is the separate Must-Staple policy).
    """
    good = scenario["status"] == "good"
    stapled = scenario["stapling"] == "on"
    fresh = scenario["freshness"] != "expired"
    reachable = bool(scenario["responder_reachable"])
    if policy == "K1":
        return "ACCEPT" if stapled and fresh and good else "REJECT"
    if policy == "K4":
        return "ACCEPT"
    if policy == "K5":
        return "ACCEPT" if good else "REJECT"
    if policy in ("K2", "K3"):
        if not fresh:
            return "REJECT"
        if stapled or reachable:
            return "ACCEPT" if good else "REJECT"
        return "ACCEPT" if policy == "K3" else "REJECT"
    raise ValueError(f"unknown E6 policy {policy}")


def five_policies(host: str, port: int, ca: Path, crl: Path, truststore: Path, *, namespace: str | None = None):
    check_target(host)
    if namespace:
        results = []
        for policy in ("K1","K2","K3","K4","K5"):
            cmd = exec_in(namespace, [sys.executable, "-m", "tlslab.revocation",
                         "--host", host, "--port", str(port), "--ca", str(ca),
                         "--crl", str(crl), "--truststore", str(truststore),
                         "--policy", policy])
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT/"harness")
            try:
                run = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True,
                                     text=True, timeout=25)
                observed = json.loads(run.stdout)
                results.append(observed)
            except (ValueError, json.JSONDecodeError, subprocess.TimeoutExpired, OSError):
                results.append({"policy":policy, "outcome":"BLOCKED", "reason":"namespace probe failed"})
        return results
    return [
        k1_curl(host, port, ca),
        java_policy(host, port, "K2", truststore),
        java_policy(host, port, "K3", truststore),
        java_policy(host, port, "K4", truststore),
        k5_python_crl(host, port, ca, crl),
    ]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--ca", type=Path, default=Path("pki/out/ca.crt"))
    p.add_argument("--crl", type=Path, default=Path("pki/out/crl.pem"))
    p.add_argument("--truststore", type=Path, default=Path("pki/out/truststore.p12"))
    p.add_argument("--policy", choices=("K1","K2","K3","K4","K5"))
    args = p.parse_args()
    if args.policy == "K1":
        result = k1_curl(args.host, args.port, args.ca)
    elif args.policy in ("K2","K3","K4"):
        result = java_policy(args.host, args.port, args.policy, args.truststore)
    elif args.policy == "K5":
        result = k5_python_crl(args.host, args.port, args.ca, args.crl)
    else:
        result = five_policies(args.host, args.port, args.ca,
                               args.crl, args.truststore)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
