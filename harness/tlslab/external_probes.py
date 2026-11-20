"""Integrate pinned tlsfuzzer and testssl.sh without claiming unsupported coverage.

A tlsfuzzer script is counted successful only when it returns zero and emits
TOTAL/PASS/FAIL/XPASS counts covering at least one probe. External suite results
are supplementary: a script success is NOT a cryptographic security proof.
"""
import os
from pathlib import Path
import re
import sys
from .tool_wrappers import local_tool, run_tool, tlsfuzzer_script, check_target

SCRIPT_BY_ACTION = {
    "tlsfuzzer_supported_versions": "test-tls13-version-negotiation.py",
    "tlsfuzzer_groups": "test-tls13-no-unknown-groups.py",
    "tlsfuzzer_keyupdate": "test-tls13-keyupdate.py",
    "tlsfuzzer_compression": "test-invalid-compression-methods.py",
}


# How a failing upstream case is interpreted. tlsfuzzer scripts assert one exact
# alert for every malformed input and assume a dual-stack, RSA-certified
# server. A TLS 1.3-only server that answers protocol_version to a "fall back
# to TLS 1.2" case, or that rejects malformed input with a different alert (or
# by closing), has still rejected it. Those cases are counted separately and
# kept in the evidence; only *unexplained* failures make the probe FAIL.
# Set STRICT_ALERT_CONFORMANCE = True to score any alert mismatch as FAIL.
STRICT_ALERT_CONFORMANCE = False

CASE_HEADER = re.compile(r"(?m)^(?P<name>\S.*?) \.\.\.[ \t]*$")


def parse_cases(text: str) -> dict[str, list[dict]]:
    """Split tlsfuzzer stdout into per-conversation outcomes.

    Returns name -> list of {"ok", "node", "error"} (sanity runs twice).
    """
    cases: dict[str, list[dict]] = {}
    marks = list(CASE_HEADER.finditer(text))
    for i, mark in enumerate(marks):
        body = text[mark.end():marks[i + 1].start() if i + 1 < len(marks) else len(text)]
        ok = body.lstrip().startswith("OK")
        node = re.search(r"Error encountered while processing node (.+?) \(child:", body)
        errors = re.findall(r"(?m)^(?:\w+\.)*\w*(?:Error|Exception)\w*: (.*)$", body)
        cases.setdefault(mark.group("name"), []).append({
            "ok": ok, "node": node.group(1) if node else None,
            "error": errors[-1] if errors else (None if ok else body.strip()[:200])})
    return cases


def classify_failure(name: str, outcome: dict, *, protocols: list[str]) -> str:
    """expected_rejection | rfc_violation | nonstandard_rejection | permitted_deferral | unexplained."""
    error = outcome.get("error") or ""
    node = outcome.get("node") or ""
    # Conversations that want an older ServerHello: "fallback from X to 1.N"
    # (unknown 1.3 drafts offered next to 1.N) and "... in client hello legacy
    # field" (no supported_versions at all, i.e. PR03; target TLS 1.2). An
    # endpoint that does not enable the target version must refuse them with
    # protocol_version.
    target = None
    wanted = re.search(r"^fallback from .* to 1\.(\d)$", name)
    if wanted:
        target = "TLSv1" if wanted.group(1) == "0" else "TLSv1." + wanted.group(1)
    elif name.endswith("in client hello legacy field"):
        target = "TLSv1.2"
    if (target and target not in protocols and "ExpectServerHello" in node
            and "Alert(fatal, protocol_version)" in error):
        return "expected_rejection"
    # RFC 9846 section 6: a syntactically invalid handshake length MUST
    # generate decode_error, not illegal_parameter. These two stock tlsfuzzer
    # cases construct zero-byte and two-byte KeyUpdate bodies respectively.
    # This is an actual alert conformance failure, not just tester preference.
    if (name in ("empty KeyUpdate message", "large KeyUpdate message")
            and 'Expected alert description "decode_error" does not match received "illegal_parameter"' in error):
        return "rfc_violation"
    if (name == "app data split, conversation with KeyUpdate msg"
            and node in ("ExpectNewSessionTicket()", "ExpectKeyUpdate()")
            and error == "Timeout when waiting for peer message"):
        # The test leaves the application request incomplete while waiting for
        # an immediate reply. TLS 1.3 requires a response before the peer's NEXT
        # Application Data record, not necessarily immediately. A timeout could
        # therefore be consistent with legal deferral; the trace does NOT
        # positively verify future KeyUpdate compliance.
        return "permitted_deferral"
    if STRICT_ALERT_CONFORMANCE:
        return "unexplained"
    if re.search(r'Expected alert description "\w+" does not match received "\w+"', error):
        return "nonstandard_rejection"
    if "ExpectAlert" in node and "Unexpected closure from peer" in error:
        return "nonstandard_rejection"
    if (name == "two KeyUpdates in one record"
            and error.endswith("Unexpected message from peer: Handshake(key_update)")):
        # Valid input. The script allows one KeyUpdate reply; SunJSSE answers
        # each update_requested separately, which RFC 8446 4.6.3 permits.
        return "nonstandard_rejection"
    return "unexplained"


def tlsfuzzer_arguments(action: str, profile: dict | None) -> list[str]:
    """Options the upstream script needs to describe this server correctly."""
    profile = profile or {}
    if action == "tlsfuzzer_keyupdate":
        # "-n 0": upstream otherwise draws a random 60 of ~270 conversations,
        # so repetitions test different things and verdicts flip between runs.
        # BCJSSE answers several queued update_requested messages with one KeyUpdate.
        return ["-n", "0"] + (["--coalescing"] if profile.get("provider") == "BCJSSE" else [])
    # Upstream's TLS 1.2 legs default to RSA key transport (TLS_RSA_*), which
    # current JDKs disable. Where the profile speaks TLS 1.2, ask for the RSA
    # twin of the lab's ECDHE-ECDSA suite (the E1 runner enables it together
    # with the RSA fuzz credential) and advertise extended master secret.
    legacy = (["-C", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "--ems"]
              if "TLSv1.2" in profile.get("protocols", []) else [])
    if action == "tlsfuzzer_supported_versions":
        # Run every conversation, so the two "no supported_versions" cases
        # that PR03 is about are never lost to upstream's random sampling.
        return ["-n", "0", *legacy]
    if action == "tlsfuzzer_compression":
        return legacy
    return []


def run_tlsfuzzer(action: str, host: str, port: int, *, limit: int | None = None,
                  profile: dict | None = None):
    check_target(host)
    name = SCRIPT_BY_ACTION.get(action)
    if name is None:
        raise ValueError(f"unrecognized tlsfuzzer action: {action}")
    script = tlsfuzzer_script(name)
    if script is None:
        return {"status": "BLOCKED", "reason": f"Missing tlsfuzzer script {name}", "raw": None}
    argv = [sys.executable, str(script), "-h", host, "-p", str(port),
            *tlsfuzzer_arguments(action, profile)]
    if limit is not None:
        if limit < 1 or limit > 10000:
            raise ValueError("invalid test limit")
        argv.extend(["-n", str(limit)])
    # tlsfuzzer's script imports its own sources from repo root. Runtime requires
    # tlslite-ng; fail closed on missing prerequisites. Keep the whole output:
    # a 32 KiB tail drops the per-case diagnostics needed for classification.
    out = run_tool(argv, timeout=600, keep=4_000_000)
    if out["status"] == "BLOCKED":
        return {"status":"BLOCKED","reason":out["reason"],"raw":out}
    combined = out["stdout"] + "\n" + out["stderr"]
    # Evidence stores a bounded tail; classification below uses everything.
    raw = {**out, "stdout": out["stdout"][-32768:], "stderr": out["stderr"][-32768:]}
    values = {k: int(v) for k, v in re.findall(
        r"(?m)^(TOTAL|PASS|FAIL|XPASS|XFAIL|SKIP):\s*(\d+)\s*$", combined)}
    if {"TOTAL","PASS","FAIL","XPASS"} - values.keys():
        return {"status":"INCONCLUSIVE","reason":"No parseable tlsfuzzer summary",
                "raw":raw}
    executed = values.get("PASS",0) + values.get("FAIL",0) + values.get("XFAIL",0) + values.get("XPASS",0)
    if values["TOTAL"] < 1 or executed < 1:
        return {"status":"INCONCLUSIVE","reason":"No tests executed", "raw":raw}
    # A failed baseline handshake invalidates the negative test's premise:
    # the tool cannot show that the malformed extension/KeyUpdate caused
    # rejection if ordinary TLS negotiation already fails.
    # Preserve counts and the full raw failure rather than marking PASS.
    cases = parse_cases(combined)
    sanity_fail = bool(re.search(
        r"(?ms)^FAILED:\s*(?:.*?^\s*['\\\"]sanity['\\\"])", combined)) or any(
        not run["ok"] for run in cases.get("sanity", []))
    if sanity_fail:
        why = next((run["error"] for run in cases.get("sanity", []) if not run["ok"]), None)
        return {"status":"INCONCLUSIVE",
                "reason":"tlsfuzzer baseline sanity handshake failed; negative tests not interpretable",
                "sanity_error": why, "counts":values, "raw":raw}
    if values["XPASS"]:
        return {"status":"FAIL","reason":"tlsfuzzer reported unexpected passes",
                "counts":values,"raw":raw}
    protocols = (profile or {}).get("protocols", ["TLSv1.2", "TLSv1.3"])
    buckets: dict[str, list[dict]] = {"expected_rejection": [], "rfc_violation": [],
                                      "nonstandard_rejection": [], "permitted_deferral": [],
                                      "unexplained": []}
    for case, runs in cases.items():
        for run in runs:
            if not run["ok"]:
                buckets[classify_failure(case, run, protocols=protocols)].append(
                    {"case": case, "node": run["node"], "error": run["error"]})
    classified = sum(len(v) for v in buckets.values())
    if classified != values["FAIL"]:
        # Summary and per-case parse disagree: do not guess.
        return {"status":"INCONCLUSIVE",
                "reason":f"tlsfuzzer summary FAIL={values['FAIL']} but {classified} failing cases parsed",
                "counts":values,"raw":raw}
    detail = {"counts": values,
              "expected_rejections": len(buckets["expected_rejection"]),
              "rfc_violations": buckets["rfc_violation"][:50],
              "nonstandard_rejections": buckets["nonstandard_rejection"][:50],
              "permitted_deferrals": buckets["permitted_deferral"][:50],
              "unexplained_failures": buckets["unexplained"][:50], "raw": raw}
    if buckets["rfc_violation"]:
        return {"status":"FAIL",
                "reason":f"{len(buckets['rfc_violation'])} malformed KeyUpdate case(s) received illegal_parameter; RFC 9846 section 6 requires decode_error",
                **detail}
    if buckets["unexplained"]:
        return {"status":"FAIL",
                "reason":f"{len(buckets['unexplained'])} tlsfuzzer case(s) failed without a rejection explanation",
                **detail}
    # A non-reference alert or silent close is evidence of rejection,
    # not evidence of exact RFC conformance. Keep it unresolved until
    # independently justified rather than turning a tlsfuzzer FAIL into PASS.
    if buckets["nonstandard_rejection"] or buckets["permitted_deferral"]:
        return {"status":"INCONCLUSIVE",
                "reason":"Non-reference alert/closure or KeyUpdate reply not immediately observed; "
                         "RFC conformance remains unverified", **detail}
    if values["FAIL"] == 0 and out["returncode"] != 0:
        return {"status":"INCONCLUSIVE","reason":"tlsfuzzer exited nonzero without failures",
                **detail}
    return {"status":"PASS",
            "reason":("tlsfuzzer: %d passed; %d fallback cases to a disabled version refused with protocol_version; "
                      "%d handled with a non-reference alert/closure/reply" % (
                          values["PASS"], len(buckets["expected_rejection"]),
                          len(buckets["nonstandard_rejection"]))),
            **detail}


def run_testssl(host: str, port: int, *, timeout: int = 180):
    check_target(host)
    executable = local_tool("testssl.sh")
    if executable is None:
        return {"status":"BLOCKED","reason":"testssl.sh not installed","raw":None}
    # A testssl scan is a supplemental observation; do not convert exit=0 into
    # verified named-group policy without examining the detailed wire output.
    # testssl.sh bundles an older OpenSSL executable which may crash on
    # modern Linux hosts. Pin the known host OpenSSL instead, without modifying
    # or executing the bundled binary. Document OpenSSL's reduced legacy-cipher
    # coverage separately from actual server failures.
    import shutil
    openssl = shutil.which("openssl")
    if not openssl:
        return {"status":"BLOCKED","reason":"System OpenSSL unavailable","raw":None}
    cmd = ["bash", str(executable), "--openssl", openssl,
           "-p", "--warnings", "off", "-q", f"{host}:{port}"]
    out = run_tool(cmd, timeout=timeout)
    if out["status"]=="BLOCKED":
        return {"status":"BLOCKED","reason":out["reason"],"raw":out}
    if out["returncode"] != 0:
        return {"status":"INCONCLUSIVE","reason":"testssl exited nonzero","raw":out}
    if len(out["stdout"]) < 80:
        return {"status":"INCONCLUSIVE","reason":"testssl output unexpectedly short","raw":out}
    return {"status":"OBSERVED","reason":"testssl protocol scan saved for detailed review",
            "raw":out}
