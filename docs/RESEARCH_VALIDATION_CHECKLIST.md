# Scientific verification gate checklist (status: 19 November 2026)

**Definition:** a runner finishing is not the same as publication-ready evidence.
The user's gitignored local results were summarized in chat; they have NOT
been independently reprocessed by GitHub CI or by this checklist. Keep
reported, independently tested, and publication-qualified states separate.

## Implemented and exercised in CI

- [x] C1 server and JDK 27 Java builds, SunJSSE/BCJSSE smoke.
- [x] Python and Java test suites, cryptographic vectors, isolated pilot coverage.
- [x] E1 version-negotiation oracle corrected and tested against OpenSSL 3.
- [x] E1 B3 temporary RSA fuzz certificate, KeyUpdate classification and
      retrying OCSP field-level checker (no fabricated PASS).
- [x] E7 nginx/OpenSSL B3 reference *implementation* with a 0 ms
      off/warm/cold **pilot** and complete reference-factor plan.
- [x] Output separation for original E7 vs independent B3 reference
      (data/raw/E7 vs data/references/E7, private material gitignored).
- [x] Audit script that rejects incomplete E7/B3 reference factor coverage
      or environmental mismatch; descriptive UNPAIRED comparisons only.
- [x] E1 artifact gate requires one complete 528-cell run and does not pool
      old partial/scoped campaigns.

## Original laptop observations (operator-reported, not independently audited)

- [x] E1 planned 528 factor cells have reconciled outcomes across original
      and later targeted runs: PASS 432, FAIL 60, N/A 36, no unresolved cells.
- [x] E2: 24 x 50 captured/verified handshake observations reported.
- [x] E3: 360 JMH observations reported.
- [x] E4: 240 full 512 MiB HTTPS transfers reported.
- [x] E5: 160 hybrid/classical handshake-latency observations reported.
- [x] E6: 600 PKI/revocation policy results and zero mismatches reported.
- [x] E7: 180 Java OCSP-latency observations reported; manifest PARTIAL.

The ticks above mean 'reported as executed', NOT that all their
per-row source evidence has been independently confirmed. Never treat
the 60 E1 FAIL outcomes as failures of the test harness merely because
they are FAIL.

## Still needed for publication-qualified research

- [ ] Run **one new full 528-cell E1 campaign** using the final code;
      preserve and independently reproduce PR15/PR22 deviations and audit
      B1/B3 intentionally permissive HC controls (PR07/PR19/PR21).
- [ ] Independently audit E2 cryptographic verification and exported-secret
      security; re-deriving upstream (EC)DHE/ML-KEM shared secrets remains
      outside current verifier scope.
- [ ] Independently audit E3 thermal/governor controls, CPU-time metrics and
      JMH environment across the original 360 rows.
- [ ] Independently audit E4 large-record sizes, suite negotiation and
      throughput/CPU attribution across the original 240 rows.
- [ ] Independently audit E5 negotiated groups, PSK/HRR exclusions and timing
      sample boundaries across original 160 rows.
- [ ] Independently audit E6 certificate/OCSP/CRL scenarios and signature
      evidence across original 600 policy checks.
- [ ] **Re-execute E7 Java and isolated nginx/OpenSSL B3 180-cell datasets** on the same laptop with the corrected matched timed-client thermal windows. The first full B3 reference physically measured 180/180, but 84 were validated and 96 rejected for thermal counter changes under the older broad window. Neither run may be relabeled retroactively.
- [ ] Run the E7 comparative audit against explicit main and reference
      paths; review cross-run confounders and refrain from invalid paired
      significance tests.
- [ ] Produce evidence-gated F1–F6/T1–T7 artifacts and interpretation
      using one independently selected, validated dataset per study.
- [ ] Lock source SHA, JDK, providers, Python libraries, OpenSSL, nginx,
      CPU/governor/thermal states and measurement scripts; independent
      literature novelty and external replication remain outstanding.

Main entrypoints:

    PYTHONPATH=harness python -m tlslab.run_experiment E1 --run
    PYTHONPATH=harness python -m tlslab.run_experiment E7 --run --pilot --reference-b3
    sudo -E env PATH="$PATH" PYTHONPATH="$PWD/harness" "$(command -v python)" -m tlslab.run_experiment E7 --run --isolated --reference-b3
    PYTHONPATH=harness python -m tlslab.analysis.audit_e7_reference --main <original-e7-run> --reference <new-b3-run>
    PYTHONPATH=harness python -m tlslab.analysis.artifacts --figures --tables --strict

Never commit PKI private keys, plaintext TLS secrets or captured decrypted
user data. Preserve every historical run; never rewrite a FAIL to PASS.


## Implementation update — 20 November 2026

A new E1 full 528-cell `COMPLETE` campaign was audited
with `scripts/report_e1.py`: 432 PASS, 60 FAIL, 36 N/A, no missing,
duplicate, BLOCKED or INCONCLUSIVE cells. The 60 FAIL findings remain
preserved and require precise probe-by-probe interpretation.

The selected complete E2–E6 runs passed the repository's automated structural
audit: E2 24, E3 360, E4 240, E5 160, E6 600 rows. E7's new Java main
`20261120T113438Z_4ebc6f59f688` and nginx reference
`20261120T095847Z_3ad4d66167d1` each had 180 validated observations;
the comparative audit passed with **descriptive, unpaired** limitations.
A second B3 reference run with a different premeasurement thermal threshold
also completed, but is not silently pooled with the selected pair.

F1–F6 and T1–T7 were generated using the selected-run temporary view,
correcting the F5 E5 field name and T7 E6 certificate-status interpretation.
The underlying private raw
datasets remain gitignored. This completes the **implementation
and automated-evidence milestone**, not independent cryptographic verification,
external replication, statistical causality, or literature novelty review.
Use `scripts/generate_final_artifacts.py` and
`configs/artifact-selection.example.json` to reproduce the selection locally.
