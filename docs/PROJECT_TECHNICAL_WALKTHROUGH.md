# TLS 1.3 Hardening & Protocol Analysis — Engineering Walkthrough and Lessons Learned

**Version:** 20 November 2026 · **Repository:** https://github.com/Varun-CHINTHANIPPU/TLSpectre · **Status:** Implementation complete; independent publication verification remains open.

## 1. What this project does

The project is a reproducible, multi-layer TLS 1.3 laboratory. It does not implement TLS cryptography from scratch as a production provider; instead it configures real Java and nginx/OpenSSL TLS stacks, drives deliberately varied clients and test cases, captures cryptographic/network evidence, and subjects the resulting measurements to automated validity gates. The central engineering question is not merely “does a handshake succeed?” but “what behavior occurred, under which negotiated configuration, with which cryptographic and environmental evidence, and can it be reproduced without altering earlier observations?”

The system combines eight components: **C1** TLS servers, **C2** disposable PKI and revocation services, **C3** clients, **C4** JMH cryptographic benchmarks, **C5** experiment orchestration, **C6** conformance probes, **C7** cryptographic verification, and **C8** analysis/reporting. They support seven experimental campaigns, **E1–E7**.

## 2. End-to-end architecture

```text
YAML configuration and frozen factor matrix
                    |
                    v
Python harness (experiment selection, seeded randomized blocks)
                    |
       +------------+----------------------+
       |            |                      |
Java SunJSSE/BCJSSE nginx/OpenSSL B3     PKI/OCSP/CRL fixtures
       |            |                      |
       +------------+----------------------+
                    |
      Linux network namespaces / netem RTT / CPU controls
                    |
      Java/curl/OpenSSL clients and JMH benchmark
                    |
      Captures, logs, traffic secrets, timing observations
                    |
      Per-row evidence checks -> Parquet + JSONL + manifest
                    |
       Structural audits / E7 reference comparison
                    |
         F1–F6 figures and T1–T7 tables
```

**C1, TLS servers:** Java TLS endpoints use SunJSSE and BCJSSE, while B3 provides an independent nginx/OpenSSL implementation. YAML profiles distinguish hardened settings, baselines and performance ablations. A comparison is meaningful only when the profile, provider, certificate and negotiated cipher/group are recorded.

**C2, PKI:** Local scripts generate disposable certificates, a CA, truststores, revocation cases, OCSP response material and Must-Staple variants. OCSP AIA addresses must be reachable from the correct network namespace. Private material belongs in gitignored local paths.

**C3, clients:** Java handshake and bulk-transfer clients generate timed traffic; curl, OpenSSL and Python-based policy clients exercise revocation behavior. Untimed diagnostic captures are deliberately distinguished from timed measurement batches.

**C4, cryptographic benchmark:** Java Microbenchmark Harness (JMH) measures AEAD primitive behavior across algorithms, providers and payload sizes. This is separate from full TLS transfer goodput: an AEAD microbenchmark does not account for TCP, record framing, certificates, scheduling or network effects.

**C5, orchestration:** Python defines the factor plans, starts services, applies network/CPU controls, records manifests, and uses deterministic per-block randomization to limit ordering bias. Isolated experiments need Linux namespaces and `tc` network emulation.

**C6, conformance:** 22 probes exercise protocol negotiation, malformed messages and configuration controls. They combine third-party fuzzing, custom wire-level oracles and profile-aware policy checks. A probe FAIL is a result, not necessarily an exploitable vulnerability.

**C7, cryptographic verifier:** Exported TLS traffic secrets are used to independently check record AEAD authentication and Finished MACs against captured traffic, and to verify negotiated groups from ServerHello. This does **not** rederive the original ECDHE/ML-KEM shared secret from first principles.

**C8, reporting:** Each run has its own immutable evidence directory, a machine-readable manifest and row-level validity flags. Strict artifact generation refuses incomplete datasets; selected-run tooling avoids combining old experiments by accident.

## 3. How a typical experiment runs

1. A frozen factor matrix specifies the configurations and repetitions before measurement. The matrix is implemented in `harness/tlslab/experiment_matrix.py`.
2. The harness checks prerequisites and, when required, launches network namespaces and dedicated server/OCSP processes.
3. PKI, client and server settings are applied. A pilot can reveal configuration failures before a long campaign.
4. The workload executes. Timed observations and separate diagnostic wire captures are kept conceptually distinct.
5. Evidence is written to `data/raw/E*/<run-id>/` or, for the independent E7 B3 stack, `data/references/E7/<run-id>/`. Manifests describe environment, code and disposition; Parquet stores structured rows; JSONL and captures preserve lower-level evidence.
6. Validators check each row's expected factors, measurements, protocol observations and environment conditions. A pilot or invalid row cannot become publication evidence merely because the process exited successfully.
7. Analysis tools inspect the selected complete datasets. Figures and tables are generated only when their required evidence passes strict gates.

The distinction between **MEASURED**, **validated**, **COMPLETE**, **PARTIAL** and **scientifically independently verified** is essential. These terms are not interchangeable.

## 4. E1 — TLS conformance and hardening

**Goal:** Determine whether eight configured TLS stacks exhibit the intended behavior for 22 protocol and hardening probes, repeated three times: **8 × 22 × 3 = 528 observations**.

**Method:** Start the appropriate TLS profile, run each probe, record the observed alert, handshake behavior or HTTP/policy response, and classify PASS, FAIL or N/A. The full 20 November campaign was reported as **432 PASS, 60 FAIL, 36 N/A**, with zero unresolved factor cells. The historical campaign and targeted repairs are retained separately.

**What the 60 FAILs mean:** PR07 (6) and PR21 (6) involve intentionally permissive baseline policies; PR19 (3) records nginx banner exposure; PR15 (24) includes malformed KeyUpdate alert behavior and other provider-specific fuzz-script differences; PR22 (21) records TLS 1.3 compression-offer deviations. A ServerHello following a forbidden compression offer is **not** evidence that the handshake finished or that an exploit exists. The count represents repeated observations, not 60 separate bugs.

**Difficulty and resolution:** Off-the-shelf tlsfuzzer scripts were sometimes certificate-dependent or tested a broader historical version-negotiation question than the intended TLS 1.3 oracle. The team added native wire probes with valid positive controls and retained the upstream script as supplementary evidence. The nginx E1 helper required a temporary RSA fuzz credential while normal B3 retained its ECDSA certificate. nginx OCSP text had singular/plural wording variants and could fetch staples lazily; the checker was made tolerant of wording and retried an initially absent staple without pretending that text inspection verified the OCSP signature. Provider-level malformed KeyUpdate and compression differences were **documented rather than masked**.

## 5. E2 — Captured cryptographic verification

**Goal:** Check that actual captured TLS 1.3 records and Finished messages are consistent with exported traffic secrets and the negotiated handshake group.

**Method:** **2 providers × 3 cipher suites × 4 groups = 24 conditions**; each condition verifies **50 handshakes**, yielding **1,200** verification attempts. Captured encrypted records are authenticated using derived record keys/nonces from exported traffic secrets; Finished MACs are checked against the transcript-derived expectations. The plaintext ServerHello is inspected for the selected group.

**Difficulty and resolution:** Merely observing a successful TLS connection would be weak evidence of cryptographic correctness. The verifier therefore checks authentication tags and Finished messages from captures rather than relying only on server exit codes. The important limitation remains: exported secrets are an input, so the implementation does not independently recompute live classical/hybrid shared-secret generation. Keep TLS key logs and captures private.

## 6. E3 — AEAD primitive benchmarking

**Goal:** Compare AES-GCM and ChaCha20-Poly1305 primitive performance by provider, suite and message size without confusing it with full TLS throughput.

**Method:** Three suites × three sizes (64, 1,024 and 16,384 bytes) × four platform/ablation settings × ten randomized blocks = **360 measurements**. JMH reports throughput and benchmark-thread CPU time. Full-run validation requires appropriate JDK, CPU governor, turbo and thermal evidence.

**Difficulty and resolution:** JVM warm-up, JIT compilation, thermal throttling and turbo variation can create misleading differences. The harness records environmental controls and invalidates observations with thermal-throttle events rather than accepting every positive benchmark number. The remaining challenge is independent hardware replication and reviewing attribution of CPU time.

## 7. E4 — Full TLS bulk transfer

**Goal:** Quantify actual HTTPS goodput and CPU cost, rather than assuming AEAD microbenchmark rankings carry over to the network stack.

**Method:** Four TLS stack/ablation conditions × three cipher suites × twenty randomized blocks = **240 transfers**, each with a nominal **512 MiB** workload. Metrics include MiB/s and CPU ns/byte. Separate untimed packet inspection checks the negotiated suite and TLS record-size behavior.

**Difficulty and resolution:** Application-level throughput is affected by record framing, TCP buffering, scheduling, CPU load and the network path. The harness separates goodput from CPU cost, checks negotiated suites and large-record proportions, and enforces thermal constraints. Separate untimed wire checks do not prove that every timed transfer had identical record behavior; this is explicitly disclosed.

## 8. E5 — Classical versus hybrid post-quantum handshake cost

**Goal:** Compare TLS 1.3 handshake latency and wire footprint for classical groups and ML-KEM hybrid groups under controlled 0/50 ms network RTT.

**Method:** Two providers × four groups × two RTT levels × ten randomized blocks = **160 block-level observations**. Groups include X25519 and three hybrid configurations. The experiment records latency, server CPU and captured handshake flight sizes; a separate wire sample verifies TLS 1.3, the negotiated group and the absence of PSK resumption or HelloRetryRequest.

**Difficulty and resolution:** A slow handshake alone does not establish that a hybrid group was negotiated; resumption or HRR would invalidate a naïve comparison. Wire evidence checks group selection and handshake type. A reporting bug originally required a non-existent `segments` field; the artifact generator was corrected to use the actual `server_flight_records` field. The larger hybrid wire footprint should be interpreted alongside RTT and implementation effects, not treated as a universal performance result.

## 9. E6 — Certificate revocation policy behavior

**Goal:** Compare how different clients and revocation policies accept or reject certificates under OCSP stapling, Must-Staple, responder reachability, certificate status and response freshness conditions.

**Method:** **24 valid scenarios × five policy clients × five randomized blocks = 600 outcomes**. The scenario matrix distinguishes good/revoked status, stapling off/on, fresh/expired responses, Must-Staple and responder reachability. Outcomes are checked against a predefined policy expectation; staple presence/absence is inspected separately.

**Difficulty and resolution:** It is easy to confuse a certificate's `status` (for example, good or revoked) with an experiment's `status` (MEASURED). An artifact loader incorrectly applied the measurement-status rule to E6 certificate status. The fix exempts E6 from that generic status filter while preserving E6's own outcome and validation checks. Signed response material and policy results still need an independent cryptographic source audit before strong external claims.

## 10. E7 — OCSP stapling latency and independent B3 reference

**Goal:** Measure the latency impact of OCSP stapling **off**, **warm** and **cold** at **0/50 ms** responder RTT, and compare the Java stack with a separately implemented nginx/OpenSSL reference.

**Method:** Six factor conditions × 30 randomized blocks = **180 rows per stack**. Off/warm rows summarize 500 timed handshakes per block; cold rows capture one first-cold handshake per block. The main Java run and B3 reference use separate datasets, but the same Java timing client and matching host/software controls. The audit requires 180 validated rows on both sides.

**Difficulties and resolutions:**

- **Namespace startup failure:** An initial nginx reference campaign failed all 180 cells because `nginx -t` ran in the host namespace while the server address existed in the isolated namespace. Both configuration validation and startup were moved into the correct namespace; the failed campaign was preserved.
- **Thermal validation failure:** Another full B3 run measured 180 cells but validated only 84; 96 failed because the old thermal-monitoring window also included untimed server startup, priming and later diagnostic work. Both stacks were changed to monitor the same timed-client boundary, including the client JVM's in-process warm-up. The 96 old invalid cells were not retroactively accepted.
- **Keystore password mismatch:** A bad `KS_PASS` caused failed pilots and missing evidence fields. A preflight now checks the existing PKCS#12 truststore with `keytool -storepass:env KS_PASS`, without exposing the password in command arguments. Existing private PKI should not be regenerated merely to make old results pass.
- **Reference comparability:** New full runs with recorded CPU tuning and matching software passed the structural comparison: Java main `20261120T113438Z_4ebc6f59f688` and B3 `20261120T095847Z_3ad4d66167d1`, **180 validated rows each**. The main manifest may remain PARTIAL by design until separately audited.

**Reported descriptive medians (ms):**

| Stapling | RTT | Java | nginx/OpenSSL |
|---|---:|---:|---:|
| off | 0 | 7.725 | 3.772 |
| off | 50 | 7.598 | 3.776 |
| warm | 0 | 8.221 | 4.117 |
| warm | 50 | 8.367 | 4.149 |
| cold | 0 | 34.549 | 10.183 |
| cold | 50 | 134.535 | 9.735 |

The Java cold/50 ms median exceeds Java cold/0 ms by roughly 100 ms, whereas the nginx cold medians are similar. One plausible hypothesis is different first-cold-handshake stapling/fetch behavior, but the first timed cold handshake's staple state and OCSP signature were **not independently established**. The implementations were measured in separate runs with different leaf certificates; **do not claim causal superiority or paired significance**.

## 11. Artifact generation and evidence integrity

**Problem:** Old pilot, scoped, incomplete and repeated complete datasets coexist on disk. Automatically loading all of them can duplicate rows, merge incompatible commits, or block a valid complete selection. Deleting old evidence would conceal the development history.

**Solution:** `scripts/generate_final_artifacts.py` reads an explicit JSON mapping (`configs/artifact-selection.example.json`), creates a temporary directory with symlinks to **only** the selected raw run directories, invokes the original strict artifact generator, checks that all six PDFs and seven CSVs were produced, and only then copies the artifacts into `results/`. Original datasets remain untouched. The tool also writes a local selection/provenance report.

**Publication gates:** E1 requires exactly one complete 528-cell campaign; E2–E6 structural audits check factor coverage, validation flags and experiment-specific evidence; E7 compares independently run main/reference datasets and explicitly forbids invalid paired inference. A structural audit is not equivalent to an independent scientific replication.

## 12. Security engineering and repository hygiene

The project uses disposable local PKI, but the private keys, truststores, OCSP signing material, keylogs and raw captures can reveal sensitive traffic or allow impersonation within the lab. `.gitignore` excludes `pki/out/`, `data/raw/`, `data/references/`, `results/` and common key/capture extensions. The tracked-file scanner (`scripts/check_tracked_secrets.py`) rejects obvious private key PEM headers, sensitive tracked paths and selected token patterns. This is a **heuristic scan of the current Git index**, not a proof that historical commits or unusual secret formats are safe. The scanner and artifact-export CLI checks were added to GitHub Actions.

## 13. Clean checkout and reproduction

Prerequisites: Linux, JDK 27, Maven 3.9+, Python 3.12+, OpenSSL 3.x, nginx, curl, tshark/editcap, iproute2 and suitable privileges for isolated experiments. Follow the README and `docs/EXPERIMENT_RUNBOOK.md`.

```bash
git clone https://github.com/Varun-CHINTHANIPPU/TLSpectre.git
cd TLSpectre
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
make build
make bench
read -rsp 'Private lab password: ' KS_PASS; echo
export KS_PASS
make pki
make test
make test-java
python scripts/check_tracked_secrets.py
```

For full experimental replication, use explicit experiment commands, control CPU/governor/thermal state and namespace topology, retain each new run ID, and inspect `manifest.json`. A clean checkout contains **source code and test fixtures**, not the historical private datasets. Consequently, reproducing *historical figures* requires access to the matching local evidence or a new full campaign.

## 14. What was learned

1. **Protocol observations require exact oracles.** A generic fuzz-script failure, an alert-code mismatch and a configuration-policy failure are different scientific statements.
2. **A measurement is not automatically valid.** Thermal counters, CPU settings, negotiated group, record size and certificate state can invalidate a plausible-looking number.
3. **Reference implementations must be independently measured.** Reusing one stack's result as another's baseline would destroy the comparison.
4. **Failure history is evidence.** Keep the original failed nginx runs and invalid thermal cells; fix the harness, then collect fresh data.
5. **Evidence selection is part of reproducibility.** Explicit run IDs and strict factor gates are as important as the plotting code.
6. **Security and publication claims need boundaries.** Structural audits and successful CI tests are valuable, but neither establishes novel protocol vulnerabilities nor external cryptographic verification.

## 15. Current status and remaining scientific limits

The implementation, E1–E7 runners, structural audits, E7 comparison, and figure/table generation have been run to completion locally. The 60 E1 FAIL results are deliberately visible. The repository includes regression tests and CI workflows. Remaining research-level work includes independent capture/signature verification, fresh cross-host performance replication, literature novelty analysis and more rigorous attribution of the E7 cold-handshake difference.

## 16. Source map

- `README.md`: architecture, experiment summary, setup and limitations.
- `harness/tlslab/experiment_matrix.py`: exact factor matrices and randomized block order.
- `harness/tlslab/analysis/artifacts.py`: strict figure/table generation.
- `harness/tlslab/analysis/audit_measurements.py`: E2–E6 structural evidence checks.
- `harness/tlslab/analysis/audit_e7_reference.py`: 180/180 main/reference comparison and limitations.
- `docs/E1-CONFORMANCE-FINDINGS.md`: PR15/PR22, baseline findings and full E1 audit.
- `docs/EXPERIMENT_RUNBOOK.md`: setup, namespace, PKI, thermal and E7 recovery history.
- `docs/VALIDATION_RULES.md`: per-row validation criteria.
- `docs/RESEARCH_VALIDATION_CHECKLIST.md`: implementation versus publication-level evidence.
- `scripts/generate_final_artifacts.py`: explicit dataset-selection exporter.
- `scripts/check_tracked_secrets.py`: tracked-file security guard.
