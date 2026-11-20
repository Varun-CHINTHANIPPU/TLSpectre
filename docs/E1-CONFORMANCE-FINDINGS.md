# E1 TLS 1.3 conformance observations (JDK 27, November 2026)

These are reproducible **negative test observations**, not evidence of an
exploitable security vulnerability. The experimental runner's health and the
TLS provider's standards conformance are different questions.

Reference specification: [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846),
which obsoletes RFC 8446 and retains the relevant rules.

## PR15 — malformed KeyUpdate alerts: FAIL

The pinned tlsfuzzer `test-tls13-keyupdate.py` suite executed 270 cases;
the observed SunJSSE result was 267 passes and three script mismatches.
The two malformed-length cases use:

- `empty KeyUpdate message`: a one-byte KeyUpdate body truncated to zero
  bytes, expected `decode_error`, observed `illegal_parameter`.
- `large KeyUpdate message`: a one-byte KeyUpdate body padded to two bytes,
  expected `decode_error`, observed `illegal_parameter`.

RFC 9846 section 6 requires `decode_error` for messages with invalid syntax
or length, whereas `illegal_parameter` is for semantically invalid
but syntactically valid values. These two cases count as RFC-conformance failures.

The third case, `two KeyUpdates in one record`, produced an extra KeyUpdate
while the script expected a different message. It is tracked separately as
a non-reference response; no unsupported PASS/FAIL claim is made about that
subcase without further record-sequence analysis.

## PR22 — forbidden compression offer: FAIL

RFC 9846 section 4.2.2 requires every TLS 1.3 ClientHello to contain exactly
one null compression method, and requires a fatal `illegal_parameter` when
other methods are present.

Two *independent* probes now produce the same observation against the
SunJSSE lab server:

1. The tlsfuzzer-based ClientHello probe sees ServerHello after offering
   deflate plus null (`01 00`).
2. An independently constructed raw TLS record with a real X25519 key share
   sees ServerHello for both `01 00` and deflate-only (`01`).
   The valid null-only (`00`) control also receives ServerHello.

An OpenSSL TLS 1.3 reference server, using the same independent raw-wire
probe, responds to both malformed offers with fatal `illegal_parameter`.
The difference is independently reproduced by CI.

**A ServerHello is not a completed handshake.** The observation is specifically
that the malformed TLS 1.3 offer did not trigger the mandated abort before
ServerHello; it is not proof of successful application-data exchange or a
practical exploit.

## Reproduction

With the project environment, PKI and JDK already configured:

```bash
make test
make build
make tools
PYTHONPATH=harness python -m tlslab.run_experiment E1 --run --pilot --probe-ids PR15,PR22
```

For direct independent inspection, run the P1 lab server in a separate terminal
and execute:

```bash
PYTHONPATH=harness python -m tlslab.tls13_wire_probe --host 127.0.0.1 --port 8443
```

## Interpretation and next action

Do **not** change the expected alert to make the test pass, or insert a
nonstandard pre-TLS parser into the benchmark path just to mask provider
behavior. Preserve provider/version details, repeat on independent JDK builds
and providers, and separately decide whether to report the deviations upstream.
Keep E3–E7 measured-but-unvalidated status separate from E1 probe verdicts.


## Full E1 campaign: coverage and independence (reported 2026-11-19)

The local run `data/raw/E1/20261118T231228Z_5bca9e1b476a` was
reported by the experiment operator. **Raw Parquet/JSONL data are gitignored
and have not been independently examined in this document.** This section
records reported summary counts, not a second audit:

| Outcome | Total |
| --- | ---: |
| PASS | 381 |
| FAIL | 48 |
| N/A | 27 |
| BLOCKED | 66 |
| INCONCLUSIVE | 6 |
| Planned cells | 528 |

The factor matrix contained 22 probes × 8 profiles × 3 repetitions.
The 66 BLOCKED cells are the three B3 repetitions, each failing before a
probe executed (`server exited 1`); the underlying nginx startup logs have
not yet been examined. Among the other seven configurations, 456/462 cells
received definitive PASS/FAIL/N/A outcomes. In the reported matrix, P2's
PR03 and PR06 account for the six INCONCLUSIVE cells. P2 PR06 was a **test
coverage gap**: earlier harness versions returned INCONCLUSIVE without
probing BCJSSE. The revised runner now attempts a wire-level OpenSSL
cipher-negotiation check; that does not retroactively validate the old run.

The 21 PR15 FAIL cells and 21 PR22 FAIL cells represent repeated
profile/repetition observations, **not 21 independent TLS implementations**.
Six running profiles use SunJSSE, while P2 uses BCJSSE. SunJSSE PR15
reports invalid KeyUpdate lengths rejected with `illegal_parameter` in
place of `decode_error`; P2's reported FAIL relates to five unexplained
tlsfuzzer cases, which must not be conflated with SunJSSE's alert mismatch.
The 21 PR22 FAIL cells were reported with TLS 1.3 compression-deviation
observations; dual-stack profiles additionally combine TLS 1.2 test
results. Inspect each row's nested `tls13`/`tls12` evidence to attribute
its cause. A ServerHello after a forbidden compression offer establishes
non-abort at the first reply, **not handshake completion or exploitation**.

### Scoring semantics and baseline expectations

`outcome` answers the *particular probe's* question; `secure_outcome`
encodes the corresponding security-hardening interpretation when available.
Some probes (e.g. PR16–PR18) return PASS when behavior matches the
configuration even if a hardening control is deliberately disabled. PR07
(group rejection) and PR21 (SNI/Host mismatch) instead return FAIL on
acceptance of a disallowed group or mismatched host. Accordingly, a
baseline PR07/PR21 FAIL is not automatically a broken implementation;
the configured policy and server evidence must be interpreted together.
The reported three PR07 and three PR21 FAIL cells are consistent with the
unhardened B1 profile but require per-row confirmation.

For B3, `server_tokens off` still permits the nginx product name in the
Server header. Its certificate is ECDSA-only, whereas the Java E1 helper
imports an auxiliary RSA fuzz credential; this difference can invalidate a
stock tlsfuzzer sanity handshake. OCSP staples may be fetched lazily.
These are **predictions to test**, not measured B3 outcomes.

### Scoped replication without rewriting historical data

For new run IDs only (never overwrite or retrospectively reclassify existing
results):

```bash
PYTHONPATH=harness python -m tlslab.run_experiment E1 --run --configurations B3
PYTHONPATH=harness python scripts/report_e1.py
```

The scoped B3 run has 66 intended cells and will not by itself be a full
528-cell run. Its report deliberately continues to distinguish scoped
coverage from the full original matrix. If the nginx preflight still fails,
preserve the new `B3_*.log` plus `nginx-b3-error.log` and resolve the
configuration error rather than presenting blocked cells as tests.


## PR03 targeted wire oracle (implementation update 2026-11-19)

The baseline campaign and subsequent P2/B3 scoped runs reported PR03 as
INCONCLUSIVE. This is not evidence that either stack accepted TLS 1.3
without `supported_versions`. The pinned upstream
`test-tls13-version-negotiation.py` exercises 269 conversations, most
about historical draft/TLS 1.2 fallback and a certificate-dependent sanity
handshake. On the P2 TLS 1.3-only profile, 260 scripted fallback cases
received fatal `protocol_version`, while one SSL 2.0-format ClientHello
caused an unexplained close. On B3 the upstream baseline is not reliable:
a stock RSA-oriented script can fail against the ECDSA-only server, and
its 267 script FAIL counts must not be reclassified into PASS.

PR03's catalogue question is narrower: what happens to a **valid
ClientHello lacking the `supported_versions` extension**? A new direct
raw-wire oracle `tls_version_wire_probe.py` now sends a TLS 1.3 positive
control and a structurally checked ClientHello without extension 43.
Both offer real X25519 key shares plus a TLS 1.2 ECDHE-ECDSA cipher to
avoid making TLS 1.2 fallback impossible solely through cipher selection.
For these TLS 1.3-only profiles, RFC 9846 §4.2.1 requires a fatal
`protocol_version` response when the legacy version is 0x0303.
Only that response after a successful valid control produces scoped PR03
PASS; a ServerHello produces FAIL, and silence, an alternate alert, or
a failed control remains INCONCLUSIVE. The full upstream tlsfuzzer result
is retained as supplementary evidence, **never claimed as passing**.
An unexplained upstream FAIL still prevents the combined verdict from
being marked PASS. Dual-stack configurations retain the original
upstream suite semantics.

The wire oracle was exercised against a local OpenSSL 3 TLS 1.3-only
reference, with a positive-control ServerHello and the expected fatal
`protocol_version` on the mutant. A reproducible integration regression
now checks the same behavior in CI. **No post-change P2 or B3 verdict has
yet been observed here**: rerun the two scoped configurations under a
fresh run ID and inspect the `targeted_wire` and
`supplementary_tlsfuzzer` evidence separately:

```bash
PYTHONPATH=harness python -m tlslab.run_experiment E1 --run \
  --configurations P2,B3 --probe-ids PR03
python scripts/report_e1.py
```

Historical files remain immutable; scoped reruns do not substitute for
a newly executed full 528-cell matrix.


## B3 PR15/PR20 targeted remediation (implementation update 2026-11-19)

The B3 run dated 2026-11-19 recorded PR15=INCONCLUSIVE because the
unmodified upstream `tlsfuzzer` sanity handshake could not establish a
baseline with B3's ECDSA-only server certificate. The E1 runner now injects
the short-lived, separately generated RSA fuzz certificate into **only the
E1 B3 process**; outside the E1 harness the nginx B3 configuration remains
ECDSA-only. The RSA certificate is never a substitute for the lab ECDSA
certificate or its revocation/stapling evaluation.

Another upstream KeyUpdate conversation can wait for an immediate response
after sending only a partial HTTP request. TLS 1.3 requires a response to
`update_requested` **before the responder's next application-data record**,
not an instantaneous reply during an otherwise silent connection (RFC 8446
§4.6.3; retained in RFC 9846). The narrow timeout case is now recorded as
`permitted_deferral` *within the failure breakdown*, but remains an
overall **INCONCLUSIVE**, not a PASS or independently verified conformance.
Conclusive testing would need to cause further application-data output and
check that the required KeyUpdate precedes it.

PR20 previously checked only the first OCSP `-status` handshake after
nginx startup. nginx initializes stapling lazily, so the first response
may legitimately contain `OCSP response: no response sent`. The runner
now records that cold observation and retries a missing response up to
five times with a short delay. A displayed unsuccessful/revoked or otherwise
invalid response fails immediately; missing after all attempts is FAIL.
A displayed successful/good response with nextUpdate and successful
s_client exit constitutes the current PR20 **field-level** PASS; the
checker does *not* cryptographically verify the OCSP signature or binding.
A final E6/E7 publication-quality audit must verify those independently.

These are harness changes only; previously observed B3 PR15/PR20 verdicts
remain unchanged. Rerun their six scoped cells under a fresh run ID:

```bash
PYTHONPATH=harness python -m tlslab.run_experiment E1 --run \
  --configurations B3 --probe-ids PR15,PR20
python scripts/report_e1.py
```

## Final targeted E1 status reported 2026-11-19 (supersedes earlier pending notes)

The operator reported the following new, gitignored raw evidence summaries:

- P2 PR06: 3/3 PASS after changing to an actual on-wire cipher preference check.
- P2 + B3 PR03: 6/6 PASS with the direct extension-43 omission control.
  The old 269-case version-negotiation suite is still supplementary only.
- B3 PR15: 3/3 FAIL **after** adding the E1-only RSA fuzz credential.
  Each repetition reports the `large KeyUpdate message` receiving
  `illegal_parameter` instead of the expected `decode_error`.
  The separate `app data split` case timed out at
  `ExpectNewSessionTicket()`; possible KeyUpdate deferral remains
  unverified and was not converted to PASS.
- B3 PR20: 3/3 PASS after fixing the OpenSSL wording variation
  `OCSP responses: no responses sent` (plural) and retrying a lazily
  fetched staple. This establishes **field-level** successful/good
  status with nextUpdate, not independent OCSP response-signature validation.

Reconciled across the original E1 campaign and targeted reruns:
**PASS 432, FAIL 60, N/A 36, BLOCKED 0, INCONCLUSIVE 0** (528 planned cells).
This is a provenance-preserving operator summary, not a second raw-data
audit and **not a single newly executed 528-cell run**. It should not
replace independent full-matrix replication for F1/T3 publication figures.

The recorded FAIL buckets are PR15 (24), PR22 (21), PR07 (6), PR21 (6),
and PR19 (3). PR07 and PR21 partly reflect deliberately permissive baseline
policies, while PR19 reflects nginx's standard product-banner behavior.
PR15/PR22 require separate vendor-level conformance reproduction and precise
scope statements; do not silently modify their expected alerts. All previous
observations remain unchanged.

The publication gate now requires ONE independent full E1 campaign:
```bash
PYTHONPATH=harness python -m tlslab.run_experiment E1 --run
PYTHONPATH=harness python scripts/report_e1.py
```

## Full independent 528-cell campaign (operator-reported, 20 November 2026)

This section **supersedes the earlier pending-full-run status above**. The
operator executed one fresh full E1 campaign at
`data/raw/E1/20261120T142519Z_f03597fc1522` and ran
`scripts/report_e1.py` against that exact run. The local report printed:

| Verdict | Count |
| --- | ---: |
| PASS | 432 |
| FAIL | **60** |
| N/A | 36 |
| BLOCKED | 0 |
| INCONCLUSIVE | 0 |
| Total validated | **528 / 528** |

The report found **zero missing factor keys, duplicates or manifest
mismatches**; the manifest disposition was `COMPLETE`. This is a report of
locally generated, gitignored evidence, **not a second independent reproduction
from the raw packet captures**. The full report is local at
`results/reports/E1-full-audit.json`.

The 60 FAIL observations are distributed as PR07 6, PR15 24, PR19 3,
PR21 6 and PR22 21. The report's unique observations include:

- **PR07:** B1 and B3 completed TLS 1.3 handshakes with only `ffdhe2048`
  offered, contrary to the probe's disallow expectation. A baseline-policy
  finding, not by itself a universal TLS 1.3 violation.
- **PR15:** Most profiles returned `illegal_parameter` for malformed
  KeyUpdate cases expected to yield `decode_error`; P2's four tlsfuzzer
  failures lack a clear rejection explanation. Preserve these distinctions.
- **PR19:** B3 exposed the HTTP `Server` banner, despite banner-hardening
  expectations.
- **PR21:** B1 and B3 returned HTTP 200 for an SNI/Host mismatch.
  Interpret as a configuration-policy finding, not a universal TLS RFC rule.
- **PR22:** Seven profiles observed ServerHello after forbidden TLS 1.3
  compression offers from two independent clients; several dual-stack
  profiles additionally had TLS 1.2 fuzz-script failures. A ServerHello is
  **not** proof of a completed handshake or exploit.

Each profile has three repetitions. The 60 failing cells are repeated
probe/profile outcomes, not 60 independent implementations or vulnerabilities.
Do not rewrite these verdicts or soften test oracles to inflate the score.
Further RFC interpretation, wire-level replay, provider attribution and
independent reproduction remain scientific follow-up work.
