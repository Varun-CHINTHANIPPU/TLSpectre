"""E5 hybrid-group handshake measurement (16 cells x 10 randomized blocks).

Full run requires isolated namespaces and netem; session resumption and actual
named groups require independent capture verification before scientific claims.
"""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import statistics
import numpy as np

from .env import managed_host_tuning, experiment_affinity
from .evidence import new_run, append_jsonl, to_parquet, complete_manifest
from .experiment_matrix import plan
from .experiment_control import ephemeral_server_profile, running_server, run_java_csv, cpu_ns
from .wire_capture import wire_proxy, handshake_summary, connections
import psutil
from .launch import ROOT
from .netns import isolated_network, delay


def latency_percentiles(values: list[float]) -> tuple[float, float]:
    """Linear-interpolated empirical p95 and p99, including small pilots."""
    if not values:
        raise ValueError("no latency observations")
    return float(np.percentile(values, 95)), float(np.percentile(values, 99))


def java_pid(process) -> int:
    """PID of the JVM itself (ip netns exec / taskset normally exec in place)."""
    proc = psutil.Process(process.pid)
    if "java" in proc.name():
        return proc.pid
    for child in proc.children(recursive=True):
        if "java" in child.name():
            return child.pid
    raise RuntimeError("server JVM process not found")


def wire_verification(summaries: list[dict], *, group: str, expected: int) -> dict:
    """Aggregate captured handshake facts and decide whether the cell is verified."""
    groups = sorted({s["negotiated_group"] for s in summaries}, key=str)
    facts = {
        "wire_handshakes": len(summaries),
        "wire_negotiated_groups": ",".join(map(str, groups)),
        "group_verified": len(summaries) == expected and groups == [group],
        "resumption_verified": len(summaries) == expected and not any(
            s["psk_offered"] or s["psk_accepted"] or s["early_data_offered"] for s in summaries),
        "tls13_verified": all(s["tls13"] for s in summaries),
        "hrr_rate": sum(s["hrr"] for s in summaries) / len(summaries) if summaries else None,
    }
    for name in ("client_hello_bytes", "server_hello_bytes", "encrypted_server_bytes",
                 "client_flight_bytes", "server_flight_records"):
        facts[name] = statistics.median(s[name] for s in summaries) if summaries else None
    if summaries:
        facts["handshake_bytes"] = (facts["client_hello_bytes"] + facts["server_hello_bytes"]
                                    + facts["encrypted_server_bytes"] + facts["client_flight_bytes"])
    return facts


def validation_failures(record: dict, *, pilot: bool, isolated: bool) -> list[str]:
    reasons = []
    if pilot:
        reasons.append("pilot run")
    if not isolated:
        reasons.append("not run in isolated namespaces with controlled RTT")
    if record.get("status") != "MEASURED":
        return reasons + ["not measured"]
    for flag, why in (("group_verified", "negotiated group not verified on the wire"),
                      ("resumption_verified", "PSK/early data seen or not checked"),
                      ("tls13_verified", "not TLS 1.3 on the wire")):
        if not record.get(flag):
            reasons.append(why)
    if record.get("hrr_rate") not in (0, 0.0):
        reasons.append("HelloRetryRequest observed")
    return reasons


def execute(*, pilot=False, isolated=False, tune_cpu=False, bc_pilot=False):
    if bc_pilot and not pilot:
        raise ValueError("--bc-pilot requires --pilot")
    if not os.getenv("KS_PASS"):
        raise EnvironmentError("KS_PASS required")
    if not pilot and not isolated:
        raise ValueError("Full E5 requires network namespaces for 0/50ms controlled RTT")
    if not (ROOT/"java/target/tlslab-server.jar").is_file():
        raise FileNotFoundError("make build first")
    affinity = experiment_affinity()
    cases = plan("E5",blocks=1 if pilot else None)
    if pilot:
        if bc_pilot:
            # Deliberate small compatibility check for previously failing groups.
            # NOT a replacement for any full E5 condition or capture validation.
            hybrids = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}
            cases = [c for c in cases if c["rtt_ms"] == 0
                     and c["provider"] == "BCJSSE" and c["group"] in hybrids]
        else:
            cases = [c for c in cases if c["rtt_ms"]==0 and c["group"] in (
                     "x25519","X25519MLKEM768") and c["provider"]=="SunJSSE"]
    directory = new_run("E5",{"pilot":pilot,"bc_pilot":bc_pilot,"isolated":isolated,
                              "handshakes_per_cell_rtt0":2000,
                              "handshakes_per_cell_rtt50":300})
    observations=[]
    with ExitStack() as stack:
        stack.enter_context(managed_host_tuning(tune_cpu))
        if isolated:
            stack.enter_context(isolated_network())
        for i,cell in enumerate(cases):
            provider=cell["provider"]
            group=cell["group"]
            rtt=cell["rtt_ms"]
            if isolated:
                delay(rtt,ocsp=False)
            host="10.77.1.1" if isolated else "127.0.0.1"
            count = 8 if pilot else 2000 if rtt==0 else 300
            discard = 2 if pilot else 200 if rtt==0 else 30
            base = "P1" if provider=="SunJSSE" else "P2"
            profile=ephemeral_server_profile(base, {
                "bindHost":host, "namedGroups":[group],
                "cipherSuites":["TLS_AES_128_GCM_SHA256"],
                "ocspStapling":False, "sessionCache":False,
            }, directory/"profiles"/str(i))
            record={**cell,"status":"INCOMPLETE","n":0,"validated":False,
                    "group_verified":False,"resumption_verified":False}
            try:
                log_path = directory/"logs"/f"{i}.log"
                with running_server(profile,log_path,
                                    namespace="tlslab-srv" if isolated else None,
                                    server_affinity=affinity["server"]) as server:
                    # BCJSSE can initialize while rejecting every configured named group.
                    # Fail this cell immediately instead of running thousands of doomed handshakes.
                    if provider == "BCJSSE":
                        startup_log = log_path.read_text(errors="replace")
                        if "contained no usable NamedGroup values" in startup_log:
                            raise RuntimeError("BCJSSE rejected all configured named groups; see server log")
                    jvm = java_pid(server)
                    cpu_before = cpu_ns(jvm)
                    raw=run_java_csv("HandshakeClient", [
                        host,"8443","lab.test",provider,group,str(count+discard),
                        str(ROOT/"pki/out/truststore.p12")
                    ], timeout=max(120,(count+discard)*2),
                                    namespace="tlslab-cli" if isolated else None,
                                    client_affinity=affinity["client"])
                    server_cpu = cpu_ns(jvm) - cpu_before
                    # Untimed verification batch, same client code and settings,
                    # through a byte-exact capture proxy in the client namespace.
                    verify_n = 3 if pilot else 20
                    wire_dir = directory/"wire"/str(i)
                    with wire_proxy(host, 8443, wire_dir,
                                    namespace="tlslab-cli" if isolated else None) as (ph, pp):
                        checked = run_java_csv("HandshakeClient", [
                            ph, str(pp), "lab.test", provider, group, str(verify_n),
                            str(ROOT/"pki/out/truststore.p12")], timeout=120,
                            namespace="tlslab-cli" if isolated else None)
                    if any(r["status"] != "OK" for r in checked):
                        raise RuntimeError("verification handshakes through capture proxy failed")
                    summaries = [handshake_summary(c) for c in connections(wire_dir)]
                    append_jsonl(directory/"wire_evidence.jsonl", {"cell": i, **cell,
                                                                    "handshakes": summaries})
                    record.update(wire_verification(summaries, group=group, expected=verify_n))
                    record["server_cpu_ns"] = server_cpu / (count + discard)
                    record["server_cpu_scope"] = "server JVM CPU over timed batch incl. discarded warm-up, per handshake"
                if len(raw)!=count+discard or any(
                    r["status"]!="OK" or r.get("protocol")!="TLSv1.3"
                    or r.get("suite")!="TLS_AES_128_GCM_SHA256" for r in raw):
                    failures = {}
                    for row in raw:
                        if row.get("status") != "OK":
                            key = row.get("status", "MISSING_STATUS")
                            failures[key] = failures.get(key, 0) + 1
                    raise RuntimeError(
                        f"incomplete full-handshake trial: expected={count+discard}, "
                        f"received={len(raw)}, failure_statuses={failures}"
                    )
                timed=raw[discard:]
                values=[int(r["handshake_ns"])/1e6 for r in timed]
                if any(v<=0 for v in values):
                    raise RuntimeError("nonpositive timing")
                record.update({"status":"MEASURED","n":len(values),
                               "handshake_ms":statistics.median(values),
                               "p95_handshake_ms":latency_percentiles(values)[0],
                               "p99_handshake_ms":latency_percentiles(values)[1],
                               "validation_scope":"group/HRR/PSK/bytes verified on separate untimed captured handshakes with identical client settings"})
                for j,r in enumerate(timed):
                    append_jsonl(directory/"raw_handshakes.jsonl", {
                        **cell,"index":j,"handshake_ns":int(r["handshake_ns"]),
                        "tcp_ns":int(r["tcp_ns"]),
                        "negotiated_group":r["negotiated_group"],"resumption":r["resumption"]})
            except Exception as exc:
                record.update({"status":"FAILED","error":type(exc).__name__+":"+str(exc)[:400]})
            append_jsonl(directory/"measurements.jsonl",record)
            observations.append(record)
    for record in observations:
        reasons = validation_failures(record, pilot=pilot, isolated=isolated)
        record["validated"] = not reasons
        record["validation_failures"] = "; ".join(reasons) or None
    to_parquet(observations,directory/"results.parquet")
    validated = sum(bool(r["validated"]) for r in observations)
    complete_manifest(directory,"COMPLETE" if (not pilot and validated == len(observations) == 160)
                      else "PARTIAL",{
        "measured":sum(r["status"]=="MEASURED" for r in observations),
        "failed":sum(r["status"]=="FAILED" for r in observations),
        "validated":validated,
        "validation_rule":"isolated netns+RTT, wire-verified group, TLS 1.3, no HRR, no PSK/early data",
        "affinity":affinity,
    })
    return directory


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--pilot",action="store_true")
    parser.add_argument("--bc-pilot",action="store_true")
    parser.add_argument("--isolated",action="store_true")
    parser.add_argument("--tune-cpu",action="store_true")
    a=parser.parse_args()
    print(execute(pilot=a.pilot,isolated=a.isolated,tune_cpu=a.tune_cpu,
                  bc_pilot=a.bc_pilot))


if __name__=="__main__":
    main()
