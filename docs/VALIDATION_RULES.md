# When a row may be `validated=True` (E2–E7)

A row is validated only when the evidence listed here was collected **in that
run** and checked automatically. Every unvalidated row carries a
`validation_failures` column listing each missing piece. Pilots are never
validated. Manifests become `COMPLETE` only for full, non-pilot runs where every
row passed.

| Exp | Evidence required per row | Manifest COMPLETE |
|---|---|---|
| E2 | 50/50 handshakes: NSS secrets reproduce record AEAD tags and both Finished MACs, **and** the plaintext ServerHello negotiated the cell's group | 24 cells validated |
| E3 | measured; `cpu_ns_per_byte` from benchmark-thread CPU time (ThreadMXBean, once per JMH iteration); JDK ≥ 27; performance governor + turbo off at run start **and** end (`--tune-cpu`, required for full runs); cool-down gate met and **zero kernel thermal-throttle events** during the cell | 360 rows |
| E4 | measured; negotiated suite = condition; a separate untimed captured transfer shows record ciphertext ≤ 2^14+256 and ≥ 95 % of bytes in ≥ 16000-byte records; thermal window as E3; if `TLSLAB_PIN_CPU=1`, every server thread confined | 240 rows |
| E5 | `--isolated`; an untimed captured batch with identical client settings shows the requested group, TLS 1.3, no HRR, no PSK/early data | 160 rows |
| E6 | `--isolated`; outcome equals the policy expectation in `revocation.expected_outcome`; OpenSSL `s_client` in the client namespace sees the staple present/absent, with the cert status and expiry the scenario specifies | 600 rows |
| E7 | `--isolated`; JDK ≥ 27; staple state checked after timing; captured sample is full TLS 1.3 without PSK; client JVM warmed against a separate stapling-off server and server JVM warmed with status-less handshakes; thermal window | Primary 180 rows remain PARTIAL until a separately executed, fully validated nginx/OpenSSL B3 reference is available |

Thermal evidence uses `/sys/devices/system/cpu/cpu*/thermal_throttle/*_throttle_count`
(Intel). Without those counters thermal validation is impossible and rows stay
unvalidated. Tune the gate with `TLSLAB_THERMAL_MAX_C` (default 70) and
`TLSLAB_THERMAL_WAIT_S` (default 300).

### E7 timed measurement thermal boundary (20 November 2026)

After a 180/180 MEASURED reference run returned 84 validated, 96 excluded for
thermal-throttle counter changes, code review found the counter window
included **untimed server startup, 200 server warm-up handshakes, OCSP cache
priming, and subsequent wire verification**. Those steps could contribute
thermal events without occurring within the timed handshake measurements.

E7 Java and nginx B3 reference now use the **same** thermal window:
after server/cache priming and immediately before the timed-client Java
process, begin a new bounded cool-down gate and counter snapshot. Close
the window immediately after that client process returns. The Java client
may perform 200 *untimed* handshakes against the separate warm-up endpoint
in the same JVM immediately before its timed batch; these are deliberately
included in the thermal window because they affect subsequent CPU temperature.
The pilot cold test includes two per-restart windows. Any counter change
inside a window still disqualifies the measurement; no threshold was relaxed.

Old 96 thermally rejected cells remain rejected. They cannot be
retrospectively relabeled because the old run lacks timed-only counter
snapshots. For a publication comparison, both main E7 and B3 reference
must use the same newly recorded `thermal_window_scope` field, so the
audit explicitly rejects older broad-window datasets. A new full run may
still fail if the *timed* workload actually causes throttling; address
physical cooling, background CPU load and CPU operating conditions rather
than rewriting the evidence or raising acceptance thresholds. Kernel
core/package counters may report duplicated increments for a single
physical event; **zero increments on all relevant counters** is the
validation criterion, not the exact summed increment count.

Scope limits that validation does **not** remove: E2 starts from exported
traffic secrets and does not re-derive (EC)DHE/ML-KEM shared secrets; E5/E7
wire checks use a separate untimed sample, not the timed handshakes themselves
(server tickets are disabled and every client handshake uses a fresh
SSLContext, so the timed handshakes cannot resume).

Check everything on your machine with `bash scripts/verify_fixes.sh`.

## Independent E7 nginx/OpenSSL reference (implemented; final data pending)

The reference runner uses E7 --run --reference-b3 --isolated and writes to data/references/E7/. The original Java E7 data remains untouched.

- Six factor conditions per randomized block, 30 blocks (180 reference observations).
- 0 and 50 ms OCSP RTT controlled on the dedicated server-to-responder veth pair.
- A short-lived ECDSA certificate signed by the original lab CA, with an OCSP AIA routable inside the server namespace.
- Cold test: first status-request handshake is timed before a staple query. Warm test: OCSP cache is primed before timing. Off: no staple allowed.
- An untimed captured control checks TLS 1.3, no PSK/HRR; OpenSSL status output checks staple presence/status fields.
- Full reference requires thermal and namespace validation. Pilot/nonisolated rows never qualify.

The E7 reference audit requires 180 validated observations from **each stack**, complete factor coverage, and matching host CPU and installed Java/OpenSSL/nginx environments. It outputs **descriptive, unpaired** cross-run comparisons. There is no independent OCSP signature verification within the TLS stapling probe; measurements were not randomized between the Java and nginx implementations in the same wall-clock blocks. Do not apply paired statistical tests to separate runs.

F6 remains gated until the independent reference audit passes. Historical PARTIAL manifests must never be retroactively relabeled COMPLETE.

## E1 publication report selection

When historical scoped or incomplete E1 results exist, publication figures and tables require exactly **one full, independent 528-cell COMPLETE non-pilot run**. A scoped 3-, 6-, or 66-cell COMPLETE manifest is not enough; data from different commits are never silently merged. Duplicate or missing (configuration, repetition, probe_id) keys invalidate the campaign.
