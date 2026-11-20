"""E2 pcapng + Java NSS keylog experiment across 24 suite/group/stack cells."""
from __future__ import annotations
import argparse
from pathlib import Path
import os
import subprocess
import time

from .capture import capture_loopback, keylog_server_argv, inject_keylog
from .evidence import new_run, append_jsonl, to_parquet, complete_manifest
from .experiment_matrix import plan
from .experiment_control import await_tcp, ephemeral_server_profile, run_java_csv
from .launch import ROOT
from .traceverify.verify_capture import verify_capture
from .traceverify.trace import TraceError


def execute(*, pilot: bool = False):
    if not os.environ.get("KS_PASS"):
        raise EnvironmentError("KS_PASS required")
    if not (ROOT/"java/target/tlslab-server.jar").is_file():
        raise FileNotFoundError("make build first")
    expected = 2 if pilot else 50
    cells = plan("E2")[:1] if pilot else plan("E2")
    run = new_run("E2", {"pilot":pilot,"handshakes_per_cell":expected,
                         "keylog_agent_required":True,
                         "traffic_secret_verification_not_full_key_exchange":True})
    observations = []
    for i, cell in enumerate(cells):
        config = "P1" if cell["provider"]=="SunJSSE" else "P2"
        profile = ephemeral_server_profile(config, {
            "cipherSuites":[cell["suite"]], "namedGroups":[cell["group"]],
            "ocspStapling":False, "sessionCache":False,
        }, run/"profiles"/str(i))
        pcap = run/"captures"/f"{i:02d}.pcapng"
        keylog = run/"keylogs"/f"{i:02d}.keylog"
        log = run/"logs"/f"{i:02d}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        result = {**cell,"cell":i,"status":"INCOMPLETE","validated":False,
                  "verification_pass":None,"n_verified":0,"n_expected":expected}
        process = None
        try:
            argv = keylog_server_argv(profile,keylog)
            os.chmod(keylog.parent,0o700)
            with capture_loopback(pcap):
                with log.open("w") as output:
                    process = subprocess.Popen(argv, cwd=ROOT, stdout=output,
                                               stderr=subprocess.STDOUT)
                    try:
                        await_tcp("127.0.0.1",8443,process)
                        rows = run_java_csv("HandshakeClient", [
                            "127.0.0.1","8443","lab.test",
                            cell["provider"],cell["group"],str(expected),
                            str(ROOT/"pki/out/truststore.p12")
                        ],timeout=max(90,expected*3))
                        if len(rows)!=expected or any(r["status"]!="OK" for r in rows):
                            raise RuntimeError("handshake client failures or incomplete count")
                    finally:
                        if process.poll() is None:
                            process.terminate()
                        try:
                            process.wait(timeout=12)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
            checked = verify_capture(pcap,keylog)
            # A stream only counts if its plaintext ServerHello negotiated
            # this cell's group: AEAD/Finished checks alone cannot show that.
            passes = sum(r["status"]=="PASS" and r.get("negotiated_group")==cell["group"]
                         for r in checked)
            groups = sorted({str(r.get("negotiated_group")) for r in checked})
            result.update({
                "status":"MEASURED" if len(checked)==expected and passes==expected else "FAILED",
                "verification_pass":1 if len(checked)==expected and passes==expected else 0,
                "n_verified":passes, "n_captures":len(checked),
                "negotiated_groups":",".join(groups),
                "group_verified": groups == [cell["group"]],
                "validated":len(checked)==expected and passes==expected,
                "scope":"NSS secrets to TLS record AEAD and Finished, plus ServerHello group; no upstream hybrid secret derivation"
            })
            if checked:
                append_jsonl(run/"capture_verification.jsonl",{"cell":i,"streams":checked})
                inject_keylog(pcap,keylog,run/"captures"/f"{i:02d}-secrets.pcapng")
        except (Exception, TraceError) as exc:
            result.update({"status":"BLOCKED", "error":type(exc).__name__+": "+str(exc)[:400]})
        append_jsonl(run/"measurements.jsonl",result)
        observations.append(result)
    to_parquet(observations,run/"results.parquet")
    complete_manifest(run, "COMPLETE" if observations and all(r["validated"] for r in observations)
                      else "PARTIAL",
                      {"verified_cells":sum(bool(r["validated"]) for r in observations),
                       "total_cells":len(observations),"scope":"traffic secrets -> record/Finished + ServerHello group"})
    return run


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--pilot", action="store_true")
    args=parser.parse_args()
    print(execute(pilot=args.pilot))


if __name__=="__main__":
    main()
