"""Check that the E1-E7 validation fixes work on this machine.

Reads the runs listed by scripts/verify_fixes.sh (one JSON object per line:
{"label": ..., "out": ...}) and prints PASS / WARN / FAIL per check.
FAIL means a fix did not work. WARN means the code worked but this machine
cannot provide the evidence (for example no thermal-throttle counters).
Exit status 1 if anything FAILed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

from .env import controls_established

RESULTS: list[tuple[str, str, str]] = []


def report(status: str, check: str, detail: str = ""):
    RESULTS.append((status, check, detail))
    print(f"[{status:4}] {check}" + (f" -- {detail}" if detail else ""), flush=True)


def expect(ok: bool, check: str, detail: str = "", *, warn: bool = False):
    report("PASS" if ok else ("WARN" if warn else "FAIL"), check, detail)
    return ok


def load(out: str):
    run = Path(out)
    manifest = json.loads((run / "manifest.json").read_text())
    return run, manifest, pd.read_parquet(run / "results.parquet")


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.is_file() else []


def check_e1(out):
    _, _, df = load(out)
    expect(len(df) == 22, "E1 pilot ran all 22 probes", f"{len(df)} rows")
    unresolved = df[df["outcome"].isin(["BLOCKED", "INCONCLUSIVE"])]
    expect(unresolved.empty, "E1 no BLOCKED/INCONCLUSIVE probes",
           ", ".join(f"{p}={o}" for p, o in zip(unresolved.probe_id, unresolved.outcome)))
    findings = df[~df["outcome"].isin(["PASS", "N/A"])]
    report("INFO", "E1 non-PASS verdicts (documented conformance findings expected: PR15, PR22)",
           ", ".join(f"{p}={o}" for p, o in zip(findings.probe_id, findings.outcome)))


def check_e2(out):
    _, manifest, df = load(out)
    expect(len(df) == 24, "E2 full matrix: 24 cells", f"{len(df)} cells")
    expect(df["n_verified"].eq(50).all(), "E2 all 50 handshakes verified in every cell",
           f"{int(df['n_verified'].sum())}/1200")
    expect(df.get("group_verified", pd.Series([False])).eq(True).all(),
           "E2 ServerHello group equals the cell's group (new check)")
    expect(manifest["disposition"] == "COMPLETE", "E2 manifest COMPLETE", manifest["disposition"])


def check_e3(out):
    run, _, df = load(out)
    measured = df[df["status"] == "MEASURED"]
    expect(len(measured) == len(df) == 2, "E3 tuned pilot: both JMH cells measured",
           f"{len(measured)}/{len(df)} MEASURED")
    metric_columns = {"cpu_ns_per_byte", "wall_ns_per_byte"}
    if metric_columns.issubset(measured.columns) and not measured.empty:
        ratio = measured["cpu_ns_per_byte"] / measured["wall_ns_per_byte"]
        valid = (len(measured) == 2 and measured["cpu_ns_per_byte"].notna().all()
                 and ratio.between(0.5, 1.5).all())
        detail = "cpu/wall ratio " + ", ".join(f"{r:.2f}" for r in ratio)
    else:
        valid = False
        detail = "No complete JMH CPU/wall metrics; check E3 runner logs"
    expect(valid, "E3 cpu_ns_per_byte measured from thread CPU time (new)", detail)

    snapshots = {e.get("phase"): e.get("cpu", {}).get("cpu_controls", {})
                 for e in jsonl(run / "environment.jsonl")}
    tuned = all(controls_established(snapshots.get(phase, {}))
                for phase in ("start", "end"))
    expect(tuned, "E3 --tune-cpu established performance governor + turbo off at start and end",
           "CPU controls must be recorded as established in both snapshots")

    windows = [e.get("thermal") for e in jsonl(run / "evidence.jsonl")
               if e.get("status") == "MEASURED"]
    if len(windows) != 2 or any(not isinstance(w, dict) for w in windows):
        expect(False, "E3 thermal windows recorded for both JMH cells",
               f"{len(windows)}/2 measured thermal windows")
        return
    counters = all(w.get("throttle_counters", 0) > 0 for w in windows)
    expect(counters, "E3 kernel thermal-throttle counters available",
           "Missing kernel thermal_throttle counters; thermal validation impossible",
           warn=True)
    if counters:
        expect(all(w.get("ok") and w.get("throttle_events") == 0 for w in windows),
               "E3 per-cell thermal gate met and no throttle events")
    report("INFO", "E3 thermal windows",
           "; ".join(f"gate {w.get('gate', {}).get('temp_c')}C, "
                     f"events {w.get('throttle_events')}" for w in windows))


def check_e4(out):
    _, _, df = load(out)
    expect(len(df) == 12 and df["status"].eq("MEASURED").all(), "E4 pilot: 12/12 measured")
    expect(df["suite_verified"].eq(True).all(), "E4 negotiated suite == condition")
    expect(df["record_size_ok"].eq(True).all(), "E4 record sizes captured and within RFC limit (new)",
           f"max record {int(df['max_record_ciphertext'].max())} bytes")
    report("INFO", "E4 TLS records per MiB by stack (SunJSSE splits each 16 KiB write in two)",
           df.groupby("condition")["records_per_mib"].median().round(1).to_dict().__repr__())


def check_e5(out, label):
    _, _, df = load(out)
    expect(len(df) > 0 and df["status"].eq("MEASURED").all(), f"{label}: all cells measured",
           "; ".join(df.get("error", pd.Series(dtype=str)).dropna().astype(str).str[:120]))
    for flag in ("group_verified", "resumption_verified", "tls13_verified"):
        expect(df.get(flag, pd.Series([False])).eq(True).all(), f"{label}: {flag} on the wire (new)")
    expect(df.get("hrr_rate", pd.Series([1])).eq(0).all(), f"{label}: no HelloRetryRequest")
    report("INFO", f"{label}: handshake bytes",
           dict(zip(df["group"], df.get("handshake_bytes", [None] * len(df)))).__repr__())


def check_e6(out):
    _, manifest, df = load(out)
    expect(len(df) == 120, "E6 one block: 24 scenarios x 5 policies", f"{len(df)} observations")
    mism = df[df.get("matches_expectation", pd.Series([False] * len(df))) != True]
    expect(mism.empty, "E6 every outcome matches its policy expectation (new)",
           f"{len(mism)} mismatches: " + "; ".join(
               f"{r.status}/{r.stapling}/{r.freshness}/reach={r.responder_reachable} {r.policy}={r.outcome}"
               for r in mism.head(5).itertuples()))
    expect(df["validated"].eq(True).all(), "E6 staple presence/status/expiry confirmed by OpenSSL",
           "; ".join(df["validation_failures"].dropna().unique()[:3]))
    soft = df[(df.status == "revoked") & (df.stapling == "off") & (~df.responder_reachable) & (df.policy == "K3")]
    report("INFO", "E6 finding: K3 soft-fail with unreachable responder, revoked cert",
           ", ".join(soft["outcome"]))


def check_e7(out):
    run, _, df = load(out)
    expect(len(df) == 6 and df["status"].eq("MEASURED").all(), "E7 pilot: 6/6 measured",
           "; ".join(df.get("error", pd.Series(dtype=str)).dropna().astype(str).str[:160]))
    expect(df.get("full_handshake_verified", pd.Series([False])).eq(True).all(),
           "E7 captured handshakes are full TLS 1.3, no PSK (new)")
    raw = pd.DataFrame(jsonl(run / "raw_handshakes.jsonl"))
    if raw.empty:
        return expect(False, "E7 raw handshakes recorded")
    steady = raw[raw.stapling.isin(["off", "warm"])]["handshake_ms"]
    expect(steady.max() < 100, "E7 no fresh-JVM outliers in off/warm (warm-up fix)",
           f"max {steady.max():.1f} ms (was 140-370 ms before the fix)")
    med = raw.groupby(["stapling", "rtt_ms"])["handshake_ms"].median()
    report("INFO", "E7 medians (ms)", ", ".join(f"{s}/{r}={v:.1f}" for (s, r), v in med.items()))
    if ("cold", 50) in med and ("cold", 0) in med:
        expect(med[("cold", 50)] - med[("cold", 0)] >= 40,
               "E7 cold fetch crosses the 50 ms responder RTT",
               f"cold50-cold0 = {med[('cold', 50)] - med[('cold', 0)]:.1f} ms (needs netem)", warn=True)
    if ("cold", 0) in med and ("warm", 0) in med:
        expect(med[("cold", 0)] > med[("warm", 0)], "E7 cold > warm at 0 ms RTT",
               f"{med[('cold', 0)]:.1f} vs {med[('warm', 0)]:.1f} ms", warn=True)


def main() -> int:
    runs = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()]
    for item in runs:
        label, out = item["label"], item.get("out")
        print(f"\n== {label}: {out}")
        if not out:
            report("FAIL", f"{label} did not produce a run directory", item.get("error", ""))
            continue
        try:
            {"E1": lambda: check_e1(out), "E2": lambda: check_e2(out),
             "E3": lambda: check_e3(out), "E4": lambda: check_e4(out),
             "E5-SunJSSE": lambda: check_e5(out, "E5 SunJSSE pilot"),
             "E5-BCJSSE": lambda: check_e5(out, "E5 BCJSSE hybrid pilot"),
             "E6": lambda: check_e6(out), "E7": lambda: check_e7(out)}[label]()
        except Exception as exc:
            report("FAIL", f"{label} checker crashed", f"{type(exc).__name__}: {exc}")
    failed = [r for r in RESULTS if r[0] == "FAIL"]
    warned = [r for r in RESULTS if r[0] == "WARN"]
    print(f"\nSUMMARY: {sum(r[0] == 'PASS' for r in RESULTS)} PASS, {len(warned)} WARN, {len(failed)} FAIL")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
