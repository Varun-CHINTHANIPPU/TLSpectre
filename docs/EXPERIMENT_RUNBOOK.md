# E1-E7 reproduction instructions

Requirements: JDK 27, Maven, Python 3.12+, OpenSSL 3.x, nginx,
tshark/editcap, curl, Linux iproute2 (ip netns, tc) and taskset.

Installation:

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e '.[dev]'
    export KS_PASS='choose-a-lab-only-password'
    make build && make bench && make pki
    make test && make test-java

Optional external tools: bash scripts/install_tools.sh.
For E2, obtain and SHA-pin extract-tls-secrets-5.0.0.jar separately
under third_party/. No executable third-party tool is downloaded
automatically by the test runner.

Inspect experimental factor plans without executing:

    python -m tlslab.run_experiment E4

Pilot, explicitly excluded from publication analysis:

    python -m tlslab.run_experiment E4 --run --pilot

Complete E4 (12 conditions x 20 blocks, 512 MiB per condition):

    python -m tlslab.run_experiment E4 --run

E5-E7 need three Linux network namespaces to test real 0/50 ms RTT
or responder reachability. Execute with explicit privileges:

    sudo -E env PATH="$PATH" PYTHONPATH=harness \
      python -m tlslab.run_experiment E7 --run --isolated

No turbo/governor changes occur unless --tune-cpu is supplied; state
is saved and restored in a finally block.

Limitations: E1 tests with missing tlsfuzzer features are BLOCKED, not
PASS. E2 verifies downstream secrets/Finished but cannot independently
reconstruct the upstream hybrid shared secret from live captures.
E3 needs 10 JMH fork means. E4 TLS record lengths, CPU pinning and
measurement signal accuracy need independent review. E5 negotiated
groups, absence of resumption, HRR and packet bytes need capture
verification. E6 uses local-only disposable CA and K1-K5, with
fresh/expired signed OCSP DER and client responder reachability.
E7 requires independent staple/cold-cache verification.

Outputs: data/raw/E*/<timestamp_id>/manifest.json, results.parquet,
raw JSONL, and lab-only keylogs/pcapng when needed. Never publish
raw secrets or local private keys.

## Final evidence audit and E7 independent reference (November 2026)

The full E2–E6 measurements have been **reported**, but only the local
operator has access to their gitignored source files. Avoid automatically
rerunning thousands of measurements when the initial need is an audit.

Run a strict **structural** evidence consistency check, selecting exactly
one non-pilot COMPLETE run per experiment (or provide --run E2=PATH etc.):

```bash
PYTHONPATH=harness python -m tlslab.analysis.audit_measurements
```

This checks frozen factor tuples, 50/50 E2 handshake evidence, E3 CPU/thermal,
E4 record/suite/thermal flags, E5 group/PSK/HRR flags, and E6
client policy/staple consistency. It writes hashes and a report to
results/reports/E2-E6-structural-audit.json. **It does not recompute
cryptographic signatures or reproduce physical timing on an independent
machine.**

Reference pilot (no root required, 0ms RTT only):

```bash
PYTHONPATH=harness python -m tlslab.run_experiment E7 --run --pilot --reference-b3
```

Full **independent** B3 reference (must control actual 0/50ms OCSP RTT):

```bash
sudo -E env PATH="$PATH" PYTHONPATH="$PWD/harness" "$(command -v python)" \
  -m tlslab.run_experiment E7 --run --isolated --reference-b3
```

The new reference gets its own short-lived, private ECDSA certificate
signed by the original CA; its OCSP AIA points to the OCSP namespace rather
than the server's 127.0.0.1 loopback. Only the original E7 runner uses the
old Java-provider conditions. The reference runner stores its certificate
private keys only in gitignored data/references/E7/<run>/pki/.

The full reference has 30 randomized blocks × six OCSP mode/RTT conditions
and is **not yet physically executed on the target laptop**. It does not
replace the 180 original E7 Java measurements.

The full reference command returns its exact run path. Supply both actual
directories rather than placeholder names:

```bash
export E7_MAIN_DIR="data/raw/E7/your-original-180-row-run"
export E7_REF_DIR="data/references/E7/your-new-reference-run"
PYTHONPATH=harness python -m tlslab.analysis.audit_e7_reference \
  --main "$E7_MAIN_DIR" --reference "$E7_REF_DIR"
```

The audit checks complete/validated coverage and matching software and CPU.
It writes results/tables/E7-B3-reference.csv (unpaired descriptive) and its
.audit.json provenance. Its result and the F6 figure cannot be qualified if
the reference run is missing, pilot, or partial.

Do not infer independent OCSP response signature verification from s_client
text fields. Do not claim causality or use paired statistical tests across
the two separately collected implementation runs.

Finally, run **one fresh full 528-cell E1 campaign** after updating the
harness: incomplete original data and targeted reruns are valid diagnostics,
but cannot be silently pooled into a single publication run.

```bash
PYTHONPATH=harness python -m tlslab.run_experiment E1 --run
PYTHONPATH=harness python scripts/report_e1.py
PYTHONPATH=harness python -m tlslab.analysis.artifacts --figures --tables --strict
```

Treat PR15/PR22 observed provider-level conformance deviations and
deliberately permissive B1/B3 baseline outcomes as results, not mistakes to
erase. Separate program correctness from security-control scoring.

## E7 isolated nginx configuration-test correction (19 November 2026)

The operator's first full independent B3 reference run
`20261119T141418Z_d3888f26c490` collected **zero handshakes**:
180/180 factor cells reported FAIL because `nginx -t` attempted to bind
`10.77.1.1:8080` in the **host** namespace rather than the
`tlslab-srv` namespace. This is a runner orchestration error, not
a TLS or OCSP latency result. Preserve the failed run unchanged.

The nginx reference server now performs BOTH config verification
(`nginx -t`) and daemon startup inside `tlslab-srv` when
`--isolated` is enabled. Non-isolated tests still use host namespace.
New regression tests assert that configuration validation, startup,
and readiness are namespace-consistent.

Before repeating 180 conditions, test the **six-cell isolated pilot**.
It exercises three stapling modes × two OCSP responder RTTs but remains
PARTIAL by design, even when all six cells are MEASURED:

```bash
sudo -E env PATH="$PATH" PYTHONPATH="$PWD/harness" \
  "$(command -v python)" -m tlslab.run_experiment E7 --run \
  --pilot --isolated --reference-b3
```

Inspect the returned run's `results.parquet`: all six rows must have
`status=MEASURED`, with neither nginx startup errors nor missing
handshake evidence. Only then rerun the full 180-cell reference without
`--pilot`. Do not delete, edit or label the earlier failed run COMPLETE.

## E7 thermal-window remeasurement after 180 measured/84 validated (20 November 2026)

Independent B3 reference `20261119T154121Z_a9dfbc796869` (operator reported)
produced **180/180 MEASURED**, zero execution failures, but only **84/180
validated**; 96 were excluded by the original thermal window's throttle
counter changes. The 6-cell isolated pilot was 6/6 measured and PARTIAL as
expected.

The original thermal-window code began counting **before** nginx/JVM server
startup and cache priming and ended after **untimed** OCSP and wire-capture
checks. This is overly broad for per-batch timed-handshake evidence. Both
Java and nginx E7 runners now begin a fresh CPU-temperature gate and
thermal-throttle counter window **after** server/cache warm-up, and end
it **immediately after** the timed Java client finishes. The in-process
client JVM warm-up is still inside the window: its CPU load affects the
subsequent timed samples. Any counter increment during that measured
batch still invalidates the condition; the zero-throttle criterion is
not weakened.

The old 96 invalid rows **remain excluded**. A repeat run can only qualify
if each cell independently passes its new window and other evidence gates.
The main/reference comparison rejects old broad-window data, so rerun
**both main Java E7 and reference B3 E7** with matching CPU tuning and
JDK/OpenSSL/nginx versions. Effective governor/turbo state is now recorded
and compared in the manifests. A non-isolated CI pilot or the fast 3-sample
pilot does not reproduce the CPU load of a 500-handshake warm/off cell.

If the hardware supports controlled Intel power management, one option is
`--tune-cpu`, which disables turbo, selects the performance governor and
restores the previous settings when the run ends. Apply the **same option
to both** datasets. A premeasurement gate of e.g. 60 C is more
conservative than the default 70 C, but cannot prevent actual throttling
during 500 timed handshakes. Improve cooling and avoid concurrent CPU-heavy
programs; do not increase acceptance limits or alter evidence after collection.

Command pattern (lab environment and KS_PASS already exported):

```bash
# Pilot on both implementations; these are not publication evidence.
sudo -E env PATH="$PATH" PYTHONPATH="$PWD/harness" \
  TLSLAB_THERMAL_MAX_C=60 TLSLAB_THERMAL_WAIT_S=600 \
  "$(command -v python)" -m tlslab.run_experiment E7 \
  --run --pilot --isolated --reference-b3 --tune-cpu

# Full original Java and full independent B3 reference, same host controls.
# Run only after confirming the relevant pilots and cooling configuration.
sudo -E env PATH="$PATH" PYTHONPATH="$PWD/harness" \
  TLSLAB_THERMAL_MAX_C=60 TLSLAB_THERMAL_WAIT_S=600 \
  "$(command -v python)" -m tlslab.run_experiment E7 \
  --run --isolated --tune-cpu

sudo -E env PATH="$PATH" PYTHONPATH="$PWD/harness" \
  TLSLAB_THERMAL_MAX_C=60 TLSLAB_THERMAL_WAIT_S=600 \
  "$(command -v python)" -m tlslab.run_experiment E7 \
  --run --isolated --reference-b3 --tune-cpu
```

The structural comparison remains **unpaired**; it checks 180 validated
factor cells per stack, matching timed-window scope, and matching CPU
controls, among other requirements. Preserve earlier runs unchanged.

### E7 PKCS12 credential preflight

The E7 nginx and Java runners fail early if `KS_PASS` cannot decrypt
`pki/out/truststore.p12`, using JDK `keytool` with
`-storepass:env KS_PASS` so the password does not appear in command
arguments, errors or manifests. This prevents runs that previously
recorded six failed pilot cells with `java.io.IOException: keystore
password was incorrect` and no `thermal_ok` column. Check locally:

```bash
read -rsp 'Original lab keystore password: ' KS_PASS
echo
export KS_PASS
keytool -list -storetype PKCS12 -keystore pki/out/truststore.p12 \
  -storepass:env KS_PASS >/dev/null && echo 'Truststore password verified'
```

Use the original `make pki` password, not the sudo password. Do not
remove or regenerate `pki/out` to resolve this preflight; that would
change the cryptographic fixture and invalidate comparability with
historical runs. A failed run remains PARTIAL and its evidence remains
preserved.
