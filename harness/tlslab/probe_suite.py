"""PR01–PR22: active local-only probes and explicit evidence/unavailability.

A missing external tester, inability to calibrate application record boundaries,
or unsupported TLS API is BLOCKED/INCONCLUSIVE, NEVER a claimed PASS.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile

import yaml

from .evidence import append_jsonl, to_parquet
from .probe import tls_request, plain_redirect
from .tool_wrappers import check_target, local_tool, run_tool, tlsfuzzer_script
from .external_probes import run_tlsfuzzer, run_testssl
from .tls13_wire_probe import probe as independent_compression_probe
from .tls_version_wire_probe import probe as supported_versions_wire_probe
from .probe_protocol import (tls12_downgrade_sentinel, record_mutation_probe, zero_rtt_probe,
                             replay_handshake_probe, calibrate_record_index,
                             sslv3_client_hello_probe)

ROOT = Path(__file__).resolve().parents[2]
CATALOGUE = ROOT / "configs/probes/PR01-PR22.yaml"


def probe_catalogue(path: Path = CATALOGUE):
    entries = yaml.safe_load(path.read_text())["probes"]
    if [p["id"] for p in entries] != [f"PR{i:02d}" for i in range(1,23)]:
        raise ValueError("Catalogue must contain PR01..PR22 exactly once and in order")
    return entries


def result(status: str, observed: str, *, evidence: dict | None = None):
    if status not in ("PASS", "FAIL", "BLOCKED", "INCONCLUSIVE", "N/A"):
        raise ValueError("unrecognized probe status")
    return {"status": status, "observed": observed, "evidence": evidence or {}}


def security_score(action: str, profile: dict, verdict: str) -> int | None:
    """Separate behavioral conformance from actual hardening.

    PASS can mean an ablation behaved exactly as configured; it must not be
    interpreted as the security control being enabled. Unknown tests remain
    unscored, not silently counted as successful protections.
    """
    if verdict == "FAIL":
        return 0
    if verdict != "PASS":
        return None
    if action in ("hsts200", "hsts404") and not profile.get("hsts", False):
        return 0
    if action == "redirect" and not profile.get("httpRedirect", False):
        return 0
    if action == "sni_mismatch" and not profile.get("sniHostCheck", False):
        return 0
    if action in ("tls12_negotiation", "tls12_suite") and (
        "TLSv1.2" in profile.get("protocols", [])):
        return 0
    return 1


def from_command(cmd: list[str], checker, *, timeout=30):
    out = run_tool(cmd, timeout=timeout)
    if out["status"] == "BLOCKED":
        return result("BLOCKED", out["reason"], evidence=out)
    verdict, why = checker(out)
    return result(verdict, why, evidence=out)


def classify_staple(transcript: str) -> str:
    """Classify whether s_client displayed a usable-looking OCSP staple.

    s_client -status prints the response; string checks do not themselves
    establish response signature validity, responder provenance, or certificate
    binding. Those need separate verification for E6/E7 scientific claims.
    """
    # OpenSSL's s_client uses either singular (older/one certificate) or
    # plural (newer/multi-certificate) spelling. Neither indicates an invalid
    # OCSP response; both mean no staple was presented and permit a retry.
    if re.search(r"(?im)^\s*OCSP responses?:\s*no responses? sent\s*$", transcript):
        return "missing"
    valid_fields = all(s in transcript for s in (
        "OCSP Response Status: successful", "Cert Status: good", "Next Update:"))
    return "good" if valid_fields else "invalid"


def staple_probe(cmd: list[str], *, attempts: int = 5, delay: float = 1.0,
                 runner=None, sleep=None):
    """PR20: inspect and optionally retry nginx's lazy stapling cache.

    Retry only if s_client explicitly reports no staple. Preserve the first
    cold-status observation and every retry. Never call an invalid/stale/revoked
    staple a success simply because a later attempt is good.
    """
    import time
    runner = runner or (lambda argv: run_tool(argv, timeout=30))
    sleep = sleep or time.sleep
    if attempts < 1:
        raise ValueError("stapling attempts must be positive")
    history = []
    for attempt in range(1, attempts + 1):
        out = runner(cmd)
        if out.get("status") == "BLOCKED":
            return result("BLOCKED", out.get("reason", "OCSP probe unavailable"),
                          evidence={"attempts": history + [out]})
        if out.get("status") != "OBSERVED":
            return result("INCONCLUSIVE", "OCSP probe execution status not understood",
                          evidence={"attempts": history + [out]})
        state = classify_staple(out.get("stdout", "") + out.get("stderr", ""))
        history.append({**out, "staple": state})
        evidence = {"attempts": history, "first_attempt_staple": history[0]["staple"],
                    "staple_attempt": attempt, "signature_verified_by_probe": False}
        if state == "good":
            if out.get("returncode") != 0:
                return result("INCONCLUSIVE",
                              "OCSP fields present but s_client exited unsuccessfully",
                              evidence=evidence)
            return result(
                "PASS", f"Observed successful/good OCSP fields with nextUpdate on attempt {attempt}"
                        f" (initial attempt: {history[0]['staple']}); signature not independently checked",
                evidence=evidence)
        if state == "invalid":
            return result("FAIL", "OCSP response missing required good/successful/nextUpdate fields",
                          evidence=evidence)
        if attempt < attempts:
            sleep(delay)
    return result("FAIL", f"No OCSP staple sent in {attempts} status_request handshakes",
                  evidence={"attempts": history, "first_attempt_staple": "missing",
                            "signature_verified_by_probe": False})


GROUP_ALIASES = {"x25519": "x25519", "secp256r1": "secp256r1", "secp384r1": "secp384r1",
                 "secp521r1": "secp521r1", "x448": "x448",
                 "x25519mlkem768": "x25519mlkem768",
                 "secp256r1mlkem768": "secp256r1mlkem768",
                 "secp384r1mlkem1024": "secp384r1mlkem1024"}
_CALIBRATION: dict[str, dict] = {}


def native_probe(kind: str, c: dict, *extra: str):
    """Run tls13_native_probes in a subprocess that can import tlsfuzzer."""
    root = local_tool("tlsfuzzer")
    if root is None:
        return None, {"status": "BLOCKED", "reason": "tlsfuzzer checkout missing (make tools)"}
    import os
    path = os.pathsep.join([str(ROOT / "harness"), str(root), os.environ.get("PYTHONPATH", "")])
    suites = [x for x in c.get("cipherSuites", []) if x.startswith("TLS_AES") or x.startswith("TLS_CHACHA")]
    out = run_tool([sys.executable, "-m", "tlslab.tls13_native_probes", kind,
                    "--host", c["bindHost"], "--port", str(c["httpsPort"]),
                    "--suite", suites[0] if suites else "TLS_AES_128_GCM_SHA256", *extra],
                   timeout=120, extra_env={"PYTHONPATH": path})
    if out["status"] == "BLOCKED":
        return None, out
    try:
        data = json.loads(out["stdout"].strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None, {"status": "INCONCLUSIVE", "reason": "native probe output unparseable", **out}
    if "error" in data:
        return None, {"status": "BLOCKED", "reason": data["error"], **out}
    return data, out


def named_group_enumeration(c: dict):
    data, raw = native_probe("groups", c)
    if data is None:
        return result(raw["status"] if raw["status"] in ("BLOCKED", "INCONCLUSIVE") else "BLOCKED",
                      raw.get("reason", "native group probe unavailable"), evidence=raw)
    observed = data["observed"]
    accepted = set(data["accepted"])
    unknown = sorted(g for g, v in observed.items()
                     if v != "accepted" and not v.startswith("alert:") and v != "closed")
    configured = c.get("namedGroups", [])
    if not configured:
        return result("N/A", f"No named-group allow-list configured; endpoint accepts {sorted(accepted)}",
                      evidence=data)
    allowed, unmapped = set(), []
    for name in configured:
        alias = GROUP_ALIASES.get(name.lower())
        (allowed.add(alias) if alias else unmapped.append(name))
    outside = sorted(accepted - allowed)
    if outside:
        return result("FAIL", f"Groups outside the allow-list were accepted: {outside}", evidence=data)
    missing = sorted(allowed - accepted)
    untestable = [g for g in missing if observed.get(g, "").startswith(("untestable", "error"))]
    if unmapped or untestable or unknown:
        return result("INCONCLUSIVE",
                      f"Enumeration incomplete (unmapped={unmapped}, untestable={untestable}, unclear={unknown})",
                      evidence=data)
    if missing:
        return result("FAIL", f"Configured groups not honoured by the provider: {missing}", evidence=data)
    alerts = sorted({v for v in observed.values() if v != "accepted"})
    return result("PASS", f"Accepted exactly the allow-list {sorted(accepted)}; all others refused ({', '.join(alerts)})",
                  evidence=data)


def tls13_compression(c: dict):
    """Require two independent observations of TLS 1.3 compression handling.

    tlsfuzzer's custom ClientHello and a separately implemented raw-socket
    ClientHello must agree. A conflicting or missing result stays INCONCLUSIVE
    instead of laundering it into PASS/FAIL.
    """
    groups = [GROUP_ALIASES.get(g.lower()) for g in c.get("namedGroups", [])]
    classical = next((g for g in groups if g in ("x25519", "secp256r1", "secp384r1")), "x25519")
    data, raw = native_probe("compression", c, "--group", classical)
    # The raw oracle always uses X25519. It is only a valid cross-check when
    # that group is actually offered by the server's tested profile.
    if c.get("namedGroups") and "x25519" not in [g for g in groups if g]:
        return result("INCONCLUSIVE", "Independent X25519 oracle cannot verify this group's policy",
                      evidence={"tlsfuzzer": data, "native_tool": raw})
    wire = independent_compression_probe(c["bindHost"], int(c["httpsPort"]))
    evidence = {"tlsfuzzer": data, "independent_wire": wire, "native_tool": raw}
    if data is None:
        return result("INCONCLUSIVE",
                      "tlsfuzzer unavailable; raw-wire oracle retained as partial evidence",
                      evidence=evidence)
    if data["baseline"] != "accepted" or wire["cases"]["baseline"]["response"] != "server_hello":
        return result("INCONCLUSIVE", "One or both valid ClientHello controls failed",
                      evidence=evidence)
    answer = data["with_deflate"]
    if answer == "accepted":
        if wire["verdict"] == "FAIL":
            return result("FAIL",
                          "Both independent clients observed ServerHello after forbidden TLS 1.3 compression; RFC 9846 4.2.2 requires illegal_parameter",
                          evidence=evidence)
        return result("INCONCLUSIVE",
                      "tlsfuzzer received ServerHello but independent wire oracle did not corroborate",
                      evidence=evidence)
    if answer == "alert:illegal_parameter" and wire["verdict"] == "PASS":
        return result("PASS", "Both independent clients observed required illegal_parameter rejection",
                      evidence=evidence)
    return result("INCONCLUSIVE", f"TLS 1.3 compression observations disagree or lack required alert ({answer})",
                  evidence=evidence)

LEGACY_NAMES = {"-tls1_2": "TLSv1.2", "-tls1_1": "TLSv1.1",
                "-tls1": "TLSv1", "-ssl3": "SSLv3"}


def tls12_trial(c, ca, requested="-tls1_2"):
    # Lower the client security level for legacy ClientHello construction only.
    legacy = ["-cipher", "DEFAULT:@SECLEVEL=0"] if requested in ("-tls1", "-tls1_1") else []
    command = ["openssl", "s_client", requested, *legacy, "-brief",
               "-connect", f"{c['bindHost']}:{c['httpsPort']}",
               "-servername", "lab.test", "-CAfile", str(ca)]
    def check(out):
        combined = (out["stdout"] + "\n" + out["stderr"]).lower()
        if any(token in combined for token in
               ("no protocols available", "unknown option", "no cipher match")):
            return "BLOCKED", "Local OpenSSL cannot generate this ClientHello"
        version = LEGACY_NAMES[requested]
        success = out["returncode"] == 0 and f"protocol version: {version.lower()}" in combined
        allowed = version in c.get("protocols", [])
        if success == allowed and (success or
            any(token in combined for token in ("alert", "handshake failure", "unsupported protocol"))):
            return "PASS", f"{version} accepted/rejected as configured"
        return "FAIL", f"{version} negotiation differs from expected result or lacks server rejection proof"
    return from_command(command, check)


def http_tls(c, ca, path="/health"):
    return tls_request(c["bindHost"], int(c["httpsPort"]), str(ca),
                       ssl.TLSVersion.TLSv1_3, path)


def run_probe(spec, c, *, ca_file: Path, record_index: int | None = None,
              server_log: Path | None = None):
    action = spec["runner"]
    if action == "tls12_negotiation":
        return tls12_trial(c, ca_file)
    if action == "legacy_versions":
        scan = run_testssl(c["bindHost"],int(c["httpsPort"]))
        outcomes = {version: tls12_trial(c, ca_file, requested=version)
                    for version in ("-tls1", "-tls1_1", "-ssl3")}
        if outcomes["-ssl3"]["status"] == "BLOCKED":
            # OpenSSL 3.x is built without SSLv3; use a raw ClientHello instead.
            raw = sslv3_client_hello_probe(c["bindHost"], int(c["httpsPort"]))
            outcomes["-ssl3"] = result(raw["status"], raw["reason"], evidence=raw)
        if any(o["status"] == "FAIL" for o in outcomes.values()):
            return result("FAIL", "A legacy version was accepted or rejected without reliable evidence",
                          evidence={"openssl":outcomes,"testssl":scan})
        untested = [v for v,o in outcomes.items() if o["status"] in ("BLOCKED", "INCONCLUSIVE")]
        if untested:
            return result("INCONCLUSIVE", f"Rejection checked where supported; unavailable probes: {untested}",
                          evidence={"openssl":outcomes,"testssl":scan})
        return result("PASS", "All tested legacy versions rejected",
                      evidence={"openssl":outcomes,"testssl":scan})
    if action == "tls12_suite":
        return tls12_trial(c, ca_file)
    if action == "suite_order":
        # Exercise *both* SunJSSE and BCJSSE on the wire. Provider identity is
        # not grounds to skip a negotiated-cipher preference observation.
        suites = c.get("cipherSuites", [])
        if not suites:
            return result("N/A", "No server-side TLS 1.3 suite preference configured")
        cmd = ["openssl", "s_client", "-tls1_3", "-brief",
               "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
               "-connect", f"{c['bindHost']}:{c['httpsPort']}", "-servername", "lab.test",
               "-CAfile", str(ca_file)]
        def check(out):
            transcript = out["stdout"] + "\n" + out["stderr"]
            negotiated_tls13 = re.search(
                r"(?im)^\s*(?:Protocol version|Protocol)\s*:\s*TLSv1\.3\b", transcript)
            matched = re.search(
                r"(?im)^\s*(?:Ciphersuite|Cipher is)\s*:\s*(TLS_[A-Z0-9_]+)\b",
                transcript)
            if out["returncode"] != 0 or not negotiated_tls13 or not matched:
                return ("INCONCLUSIVE",
                        f"TLS 1.3 handshake/cipher not proven (exit={out['returncode']})")
            chosen = matched.group(1).upper()
            expected = next((suite for suite in suites if suite in (
                "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256")), None)
            if expected is None:
                return "INCONCLUSIVE", "Configured TLS 1.3 cipher preference is not testable"
            return ("PASS" if chosen == expected else "FAIL"), (
                f"negotiated={chosen}, configured_first={expected}, provider={c.get('provider')}")
        return from_command(cmd, check)
    if action == "tlsfuzzer_groups":
        # Upstream test-tls13-no-unknown-groups.py requires its reference
        # server's exact HRR/CCS sequence and alert; SunJSSE repeats the
        # compatibility CCS after HelloRetryRequest and answers
        # unexpected_message, so even its sanity case cannot pass. Enumerate
        # single-group ClientHellos directly instead.
        return named_group_enumeration(c)
    if action == "group_rejection":
        cmd = ["openssl", "s_client", "-tls1_3", "-brief", "-groups", "ffdhe2048",
               "-connect", f"{c['bindHost']}:{c['httpsPort']}", "-servername", "lab.test",
               "-CAfile", str(ca_file)]
        def check(out):
            transcript = out["stdout"] + "\n" + out["stderr"]
            combined = transcript.lower()
            if any(token in combined for token in
                   ("no suitable groups", "unknown option", "no protocols available")):
                return "BLOCKED", "Client cannot produce ffdhe2048-only ClientHello"
            # OpenSSL can print 'Cipher is (NONE)' after a failed handshake:
            # that string is NOT proof a forbidden group was negotiated.
            negotiated = bool(re.search(
                r"(?im)^\s*(?:protocol version|protocol)\s*:\s*TLSv1\.3\b", transcript))
            cipher = bool(re.search(
                r"(?im)^\s*(?:ciphersuite|cipher is)\s*:\s*TLS_[A-Z0-9_]+", transcript))
            if out["returncode"] == 0 and negotiated and cipher:
                return "FAIL", "TLS 1.3 handshake succeeded with only ffdhe2048 offered"
            if out["returncode"] != 0 and (
                    "alert" in combined or "handshake failure" in combined):
                return "PASS", "Server rejected ffdhe2048-only handshake"
            return "INCONCLUSIVE", "No definitive negotiation or server alert"
        return from_command(cmd, check)
    if action in ("hsts200", "hsts404"):
        target = "/health" if action == "hsts200" else "/does-not-exist"
        observed = http_tls(c, ca_file, target)
        value = observed["headers"].get("Strict-Transport-Security", "")
        wanted = bool(c.get("hsts", False))
        actual = value.startswith("max-age=63072000") and "includeSubDomains" in value
        expected_status = 200 if action == "hsts200" else 404
        return result("PASS" if actual == wanted and observed["status"] == expected_status else "FAIL",
                      f"status={observed['status']} hsts={value or 'absent'}")
    if action == "redirect":
        observed = plain_redirect(c["bindHost"], int(c["httpPort"]))
        headers = observed["headers"]
        expected = bool(c.get("httpRedirect", False))
        actual = observed["status"] == 308 and headers.get("Location", "").startswith("https://")
        if any(k.lower() == "strict-transport-security" for k in headers):
            return result("FAIL", "HSTS must never be sent on HTTP")
        return result("PASS" if expected == actual else "FAIL",
                      f"redirect status={observed['status']}")
    if action == "banner":
        observed = http_tls(c, ca_file)
        values = {k.lower(): v for k,v in observed["headers"].items()}
        return result("PASS" if "server" not in values and "x-powered-by" not in values else "FAIL",
                      f"revealed banners={set(values) & {'server','x-powered-by'}}")
    if action == "staple":
        if not c.get("ocspStapling", False):
            return result("N/A", "Server stapling disabled in this profile")
        cmd = ["openssl", "s_client", "-tls1_3", "-status",
               "-connect", f"{c['bindHost']}:{c['httpsPort']}", "-servername", "lab.test",
               "-CAfile", str(ca_file)]
        return staple_probe(cmd)
    if action == "sni_mismatch":
        context = ssl._create_unverified_context()  # deliberate SNI/Host confusion probe ONLY
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        try:
            with socket.create_connection((c["bindHost"], int(c["httpsPort"])), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="other.test") as stream:
                    stream.settimeout(5)
                    stream.sendall(b"GET /health HTTP/1.1\r\nHost: lab.test\r\nConnection: close\r\n\r\n")
                    response = http.client.HTTPResponse(stream)
                    response.begin()
                    status = response.status
            return result("PASS" if status in (400, 421) else "FAIL", f"HTTP {status}")
        except ssl.SSLError as exc:
            return result("PASS" if c.get("sniHostCheck", True) else "INCONCLUSIVE",
                          f"TLS alert {type(exc).__name__}")
    if action.startswith("record_"):
        calibration = None
        if record_index is None:
            if server_log is None:
                return result("BLOCKED", "Record mutation requires a calibrated application-data record index from capture")
            key = str(server_log)
            if key not in _CALIBRATION:
                _CALIBRATION[key] = calibrate_record_index(
                    c["bindHost"], int(c["httpsPort"]), ca_file, server_log)
            calibration = _CALIBRATION[key]
            if calibration["status"] != "CALIBRATED":
                return result("BLOCKED", "Record index calibration failed: " + calibration["reason"],
                              evidence=calibration)
            record_index = calibration["index"]
        outcome = record_mutation_probe(c["bindHost"], int(c["httpsPort"]),
                                        ca_file, action.removeprefix("record_"), record_index,
                                        server_log=server_log)
        if calibration is not None:
            outcome["calibration"] = calibration
        return result(outcome["status"], outcome["reason"], evidence=outcome)
    if action in ("tlsfuzzer_supported_versions", "tlsfuzzer_groups",
                  "tlsfuzzer_keyupdate", "tlsfuzzer_compression"):
        if (action == "tlsfuzzer_supported_versions"
                and set(c.get("protocols", [])) == {"TLSv1.3"}):
            # PR03 is a no-supported_versions ClientHello, not the whole
            # upstream 269-case draft-version/TLS 1.2 fallback suite.
            # Preserve the upstream result as separate *supplemental* evidence.
            wire = supported_versions_wire_probe(c["bindHost"], int(c["httpsPort"]))
            upstream = run_tlsfuzzer(action, c["bindHost"], int(c["httpsPort"]), profile=c)
            verdict = wire["verdict"]
            reason = wire["reason"]
            if verdict == "PASS" and upstream["status"] == "FAIL":
                verdict = "INCONCLUSIVE"
                reason += "; upstream has independently unexplained failures"
            return result(
                verdict,
                "PR03 scoped no-supported_versions check: " + reason
                + f"; supplementary tlsfuzzer status={upstream['status']} "
                  "(269-case upstream suite is NOT claimed to pass)",
                evidence={"targeted_wire": wire, "supplementary_tlsfuzzer": upstream,
                          "pr03_scope": "single valid no-supported_versions ClientHello "
                          "and a positive TLS 1.3 control; not upstream full-suite conformance"})
        if action == "tlsfuzzer_compression":
            # Upstream test-invalid-compression-methods.py performs a TLS 1.2
            # handshake and expects a TLS 1.2 alert. A TLS 1.3-only server
            # correctly answers protocol_version before compression is tested,
            # so the TLS 1.3 rule (RFC 8446 4.1.2) is probed natively and the
            # upstream script is added only where TLS 1.2 is enabled.
            modern = tls13_compression(c)
            if "TLSv1.2" not in c.get("protocols", []):
                return modern
            legacy = run_tlsfuzzer(action, c["bindHost"], int(c["httpsPort"]), profile=c)
            both = {"tls13": modern, "tls12": legacy}
            states = (modern["status"], legacy["status"])
            verdict = ("FAIL" if "FAIL" in states else "PASS" if states == ("PASS", "PASS")
                       else "BLOCKED" if "BLOCKED" in states else "INCONCLUSIVE")
            return result(verdict, f"TLS1.3: {modern['observed']} | TLS1.2: {legacy['reason']}",
                          evidence=both)
        external = run_tlsfuzzer(action, c["bindHost"], int(c["httpsPort"]), profile=c)
        status = external["status"]
        return result(status, external["reason"], evidence=external)
    if action == "downgrade_sentinel":
        if "TLSv1.2" not in c.get("protocols", []):
            return result("N/A", "RFC 8446 downgrade sentinel applies to dual-stack TLS1.2 negotiation")
        observed = tls12_downgrade_sentinel(c["bindHost"], int(c["httpsPort"]))
        return result(observed["status"], observed["reason"], evidence=observed)
    if action == "zero_rtt":
        observed = zero_rtt_probe(c["bindHost"], int(c["httpsPort"]))
        return result(observed["status"], observed["reason"], evidence=observed)
    if action == "handshake_replay":
        observed = replay_handshake_probe(c["bindHost"],int(c["httpsPort"]),ca_file,
                                          server_log=server_log)
        return result(observed["status"], observed["reason"], evidence=observed)
    raise ValueError(f"Unknown probe action: {action}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config", type=Path, default=Path("configs/server/P1.yaml"))
    p.add_argument("--ca-file", type=Path, default=Path("pki/out/ca.crt"))
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--record-index", type=int)
    args = p.parse_args()
    c = yaml.safe_load(args.config.read_text())
    check_target(c["bindHost"])
    specs = probe_catalogue()
    args.out.mkdir(parents=True, exist_ok=False)
    rows = []
    for spec in specs:
        try:
            res = run_probe(spec, c, ca_file=args.ca_file, record_index=args.record_index)
        except (OSError, ssl.SSLError, ValueError) as exc:
            res = result("INCONCLUSIVE", f"{type(exc).__name__}: {str(exc)[:500]}")
        row = {"probe_id": spec["id"], "category": spec["category"],
               "configuration": args.config.stem, "outcome": res["status"],
               "secure_outcome": security_score(spec["runner"], c, res["status"]),
               "observed": res["observed"], "timestamp_utc": datetime.now(timezone.utc).isoformat()}
        rows.append(row)
        append_jsonl(args.out/"evidence.jsonl", {"row": row, "details": res.get("evidence", {})})
    to_parquet(rows, args.out/"results.parquet")
    print(json.dumps({"out": str(args.out), "counts": {
        status: sum(row["outcome"] == status for row in rows)
        for status in ("PASS","FAIL","BLOCKED","INCONCLUSIVE","N/A")
    }}, indent=2))
    return 0 if all(r["outcome"] in ("PASS", "N/A") for r in rows) else 2


if __name__ == "__main__":
    sys.exit(main())
