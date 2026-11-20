"""E6: 24 controlled revocation scenarios x five policies x five repetitions.

Full execution requires root network namespaces; client->OCSP access is toggled
without affecting server->OCSP access. Fresh/expired DER responses are actually
signed by the ephemeral OCSP key. Every observation is retained in Parquet.
"""
from contextlib import ExitStack
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time

from .e6_pki import generate
from .evidence import new_run, append_jsonl, to_parquet, complete_manifest
from .experiment_matrix import plan
from .experiment_control import ephemeral_server_profile, running_server
from .launch import ROOT
from .netns import isolated_network, client_ocsp_access, exec_in
from .revocation import five_policies, expected_outcome


def start_static_ocsp(directory: Path, freshness: str, *, isolated: bool, log: Path):
    host = "10.77.2.2" if isolated else "127.0.0.1"
    cmd = [sys.executable, "-m", "tlslab.ocsp_static",
           "--dir", str(directory), "--freshness", freshness,
           "--bind", host]
    if isolated:
        cmd = exec_in("tlslab-ocsp", cmd)
    log.parent.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT/"harness")
    out = log.open("w")
    process = None
    try:
        process = subprocess.Popen(cmd, cwd=ROOT, env=environment,
                                   stdout=out, stderr=subprocess.STDOUT)
        # Wait for an actual reachable OCSP listener, not a fixed startup sleep.
        # In isolated mode, test connectivity from the server namespace over
        # the network path the JSSE stapling client will use.
        deadline = time.monotonic() + 12
        check = [sys.executable, "-c",
                 "import socket;socket.create_connection((" +
                 repr(host) + ",8888),1).close()"]
        if isolated:
            check = exec_in("tlslab-srv", check)
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Static OCSP responder exited; see " + str(log))
            probe = subprocess.run(check, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=3)
            if probe.returncode == 0:
                return process, out
            time.sleep(.1)
        raise TimeoutError("OCSP responder not reachable from server; see " + str(log))
    except BaseException:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        out.close()
        raise


def parse_staple_output(transcript: str):
    """Interpret OCSP response output from OpenSSL 1.x-4.x s_client.

    Do not treat absent or unparseable output as evidence of no staple.
    """
    if re.search(
        r"(?im)^OCSP responses?:\s*(?:no responses sent|no response sent|no OCSP response received)\s*$",
        transcript,
    ):
        return False, "none"
    if "OCSP Response Status: successful" not in transcript:
        return None, "UNKNOWN"
    status = (
        "revoked" if "Cert Status: revoked" in transcript
        else "good" if "Cert Status: good" in transcript
        else "other"
    )
    return True, status


def staple_expired(transcript: str):
    """True/False from the stapled response's Next Update, None if absent."""
    from datetime import datetime, timezone
    match = re.search(r"Next Update:\s*(.+?)\s*$", transcript, re.M)
    if not match:
        return None
    try:
        when = datetime.strptime(match.group(1).replace("  ", " "), "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
    return when.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)


def staple_evidence(host: str, ca: Path, *, namespace: str | None) -> dict:
    """Read the staple with OpenSSL, an implementation independent of the JDK clients."""
    cmd = ["openssl", "s_client", "-tls1_3", "-status", "-connect", f"{host}:8443",
           "-servername", "lab.test", "-CAfile", str(ca)]
    if namespace:
        cmd = exec_in(namespace, cmd)
    try:
        p = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=12)
    except (OSError, subprocess.TimeoutExpired):
        return {"stapled": None, "cert_status": "UNKNOWN", "expired": None}
    text = p.stdout + p.stderr
    stapled, status = parse_staple_output(text)
    return {"stapled": stapled, "cert_status": status,
            "expired": staple_expired(text) if stapled else None}


def evidence_consistent(scenario: dict, evidence: dict) -> list[str]:
    """Does the independently observed staple match what the scenario set up?"""
    problems = []
    if scenario["stapling"] == "off":
        if evidence["stapled"] is not False:
            problems.append(f"stapling off but staple observed={evidence['stapled']}")
        return problems
    if evidence["stapled"] is not True:
        problems.append(f"stapling on but staple observed={evidence['stapled']}")
        return problems
    if evidence["cert_status"] != scenario["status"]:
        problems.append(f"staple says {evidence['cert_status']}, certificate is {scenario['status']}")
    if evidence["expired"] is not (scenario["freshness"] == "expired"):
        problems.append(f"staple expired={evidence['expired']} for freshness={scenario['freshness']}")
    return problems


def staple_observed(host: str, ca: Path, *, namespace: str | None):
    """Independent wire check: did this server staple, and what did it say?"""
    cmd = ["openssl", "s_client", "-tls1_3", "-status", "-connect", f"{host}:8443",
           "-servername", "lab.test", "-CAfile", str(ca)]
    if namespace:
        cmd = exec_in(namespace, cmd)
    try:
        p = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=12)
    except (OSError, subprocess.TimeoutExpired):
        return None, "UNKNOWN"
    return parse_staple_output(p.stdout + p.stderr)


def stop(service, output):
    try:
        if service.poll() is None:
            service.terminate()
        try:
            service.wait(timeout=5)
        except subprocess.TimeoutExpired:
            service.kill()
            service.wait()
    finally:
        output.close()


def execute(*, pilot=False, isolated=False, blocks=None):
    if not os.environ.get("KS_PASS"):
        raise EnvironmentError("KS_PASS required")
    if not pilot and not isolated:
        raise ValueError("Full E6 requires --isolated for accurate client OCSP reachability")
    if not (ROOT/"java/target/tlslab-server.jar").exists():
        raise FileNotFoundError("make build first")
    run = new_run("E6", {"pilot":pilot, "isolated":isolated, "expected_handshakes":600})
    pki = generate(run/"e6-pki",
                   uri="http://10.77.2.2:8888" if isolated else "http://127.0.0.1:8888")
    planned = plan("E6", blocks=1 if pilot else blocks)
    if pilot:
        # Include one good and one revoked sample, not the full factor matrix.
        planned = [next(c for c in planned if c["status"]=="good" and c["stapling"]=="on"
                        and c["freshness"]=="fresh"),
                   next(c for c in planned if c["status"]=="revoked" and c["stapling"]=="off")]
    rows = []
    with ExitStack() as context:
        if isolated:
            context.enter_context(isolated_network())
        for index, scenario in enumerate(planned):
            if isolated:
                client_ocsp_access(scenario["responder_reachable"])
            client_host = "10.77.1.1" if isolated else "127.0.0.1"
            name = scenario["status"] + "_" + (
                "muststaple" if scenario["must_staple"] else "plain")
            freshness = scenario["freshness"] if scenario["freshness"] != "none" else "fresh"
            responder, stdout = start_static_ocsp(
                pki, freshness, isolated=isolated, log=run/"logs"/f"{index}-ocsp.log")
            try:
                profile = ephemeral_server_profile("P1", {
                    "bindHost": client_host, "namedGroups": ["x25519"],
                    "keyStore": str(pki/f"{name}.p12"),
                    "ocspStapling": scenario["stapling"]=="on",
                    "ocspResponderUri": "http://10.77.2.2:8888" if isolated
                                        else "http://127.0.0.1:8888",
                }, run/"profiles"/str(index))
                with running_server(profile, run/"logs"/f"{index}-server.log",
                                    namespace="tlslab-srv" if isolated else None):
                    outcomes = five_policies(
                        client_host, 8443, pki/"ca.crt", pki/"crl.pem",
                        pki/"truststore.p12", namespace="tlslab-cli" if isolated else None)
                    observed = staple_evidence(
                        client_host, pki/"ca.crt", namespace="tlslab-cli" if isolated else None)
                    staple_problems = evidence_consistent(scenario, observed)
                    for o in outcomes:
                        expected = expected_outcome(scenario, o["policy"])
                        reasons = list(staple_problems)
                        if o["outcome"] != expected:
                            reasons.append(f"outcome {o['outcome']} != expected {expected}")
                        if pilot:
                            reasons.append("pilot run")
                        if not isolated:
                            reasons.append("client OCSP reachability not controlled (not --isolated)")
                        row = {**scenario, "policy":o["policy"],
                               "staple_observed": observed["stapled"],
                               "staple_cert_status": observed["cert_status"],
                               "staple_expired": observed["expired"],
                               "outcome":o["outcome"],
                               "expected_outcome": expected,
                               "matches_expectation": o["outcome"] == expected,
                               "accept": 1 if o["outcome"]=="ACCEPT" else 0 if o["outcome"]=="REJECT" else None,
                               "condition":scenario["stapling"],
                               "validated": not reasons,
                               "validation_failures": "; ".join(reasons) or None,
                               "evidence_note":"staple read independently by OpenSSL s_client in the client namespace"}
                        append_jsonl(run/"raw_evidence.jsonl", {"row":row,"details":o})
                        rows.append(row)
            except Exception as exc:
                for policy in ("K1","K2","K3","K4","K5"):
                    rows.append({**scenario, "policy":policy, "outcome":"BLOCKED",
                                 "accept":None, "validated":False,
                                 "error":type(exc).__name__+":"+str(exc)[:300]})
            finally:
                stop(responder, stdout)
    to_parquet(rows, run/"results.parquet")
    validated = sum(bool(r["validated"]) for r in rows)
    complete_manifest(run, "COMPLETE" if (not pilot and validated == len(rows) == 600)
                      else "PARTIAL", {
        "observations": len(rows), "accepted":sum(r["outcome"]=="ACCEPT" for r in rows),
        "rejected":sum(r["outcome"]=="REJECT" for r in rows),
        "blocked":sum(r["outcome"]=="BLOCKED" for r in rows),
        "validated": validated,
        "mismatches": sum(r.get("matches_expectation") is False for r in rows),
        "validation_rule": "isolated, outcome equals policy expectation, staple presence/status/"
                           "expiry independently observed by OpenSSL as the scenario specifies",
    })
    return run


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pilot", action="store_true")
    p.add_argument("--isolated", action="store_true")
    args = p.parse_args()
    print(execute(pilot=args.pilot, isolated=args.isolated))


if __name__=="__main__":
    main()
