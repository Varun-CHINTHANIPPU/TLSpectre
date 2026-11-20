# TLS 1.3 Hardening & Protocol Analysis

An experimental **TLS 1.3 security engineering lab** with Java SunJSSE/BCJSSE servers and clients, nginx/OpenSSL comparison profiles, cryptographic capture checks, post-quantum hybrid handshake experiments, certificate-revocation policy tests, and automated analysis.

**Purpose:** a reproducible laboratory implementation, not a production TLS service or a claim of independently certified protocol conformance. Do not expose the lab server, disposable CA, OCSP responder or test credentials to the public Internet.

## Architecture

```text
configs/server/*.yaml ──> Python experiment harness ──> Java TLS server/client
                                  │                       (SunJSSE / BCJSSE)
                                  ├── nginx/OpenSSL reference (B3)
                                  ├── local PKI / OCSP / CRL test fixtures
                                  ├── isolated Linux namespaces + netem RTT
                                  ├── TLS wire captures + validation rules
                                  └── per-run manifests, JSONL, Parquet
                                                │
                                strict analysis and evidence audits
                                                │
                              F1–F6 PDF figures / T1–T7 CSV tables
```

Core directories: `java/` (Java server, clients and JMH benchmark), `harness/tlslab/` (runners, probes, capture and validation), `configs/server/` (TLS profiles), `pki/` (disposable lab CA tools), `tests/` (Python tests), `scripts/` (reports and utilities), and `docs/` (runbook, validation rules and detailed findings).

## Experiments and reported results

The following is the **operator-reported local campaign on 20 November 2026**. Raw datasets and private captures are gitignored and are **not included in this GitHub repository**. The complete runs were inspected with the project's automated audits; this is not independent external scientific replication.

| Experiment | Scope | Reported automated result |
| --- | --- | --- |
| **E1 — conformance and hardening** | 8 profiles × 22 probes × 3 repetitions = **528** | 432 PASS, **60 FAIL**, 36 N/A; 0 BLOCKED/INCONCLUSIVE; complete factor coverage |
| **E2 — captured cryptographic verification** | 24 conditions × 50 handshakes = **1,200** | 24/24 conditions passed structural audit; checks exported-secret record AEAD and Finished MACs |
| **E3 — AEAD performance** | **360** randomized JMH measurements | Structural and recorded thermal/CPU validation flags passed |
| **E4 — HTTPS bulk-transfer performance** | **240** transfers of 512 MiB | Structural audit passed; record-size/suite evidence flags checked |
| **E5 — classical and hybrid group latency** | **160** block-level measurements | Structural audit passed; separate untimed wire samples check negotiated groups, PSK and HRR |
| **E6 — certificate revocation policies** | **600** policy outcomes | Structural audit passed; recorded policy expectations matched |
| **E7 — OCSP stapling latency** | **180** Java + **180** nginx/OpenSSL reference rows | Comparative evidence audit passed; **descriptive, unpaired** cross-run comparison |

**The 60 E1 FAIL results are preserved, not hidden.** Breakdown: PR07 6, PR15 24, PR19 3, PR21 6, PR22 21. PR07 (disallowed FFDHE) and PR21 (SNI/Host mismatch) involve baseline configuration/hardening expectations; PR19 reports nginx's Server banner. PR15 records malformed KeyUpdate alert/script differences, and PR22 records a ServerHello after forbidden compression offers. These are repeated probe/profile outcomes, **not 60 distinct vulnerabilities**. The exact wire behavior, provider attribution and test-oracle limits matter; see [E1 findings](docs/E1-CONFORMANCE-FINDINGS.md).

**Evidence boundaries:** E2 starts from exported TLS traffic secrets rather than independently rederiving (EC)DHE/ML-KEM shared secrets. E5/E7 wire checks use separate untimed handshakes. E6's OCSP signature verification has not been independently reproduced. E7's Java/nginx comparison uses different certificates and separate, non-interleaved runs; no causal or paired statistical claim is made.

## Prerequisites

- **Linux** with JDK **27**, Maven **3.9+**, Python **3.12+**, OpenSSL **3.x**, nginx, curl, `tshark` and `editcap`, and `iproute2` (`ip netns`, `tc`).
- Root/sudo access **only for experiments requiring isolated network namespaces and traffic shaping**. Never run untrusted network scripts as root.
- Optional testssl.sh/tlsfuzzer tools for extended conformance probes, installed using `make tools`. E2 requires its separately pinned instrumentation agent (see `make e2-agent`).
- A private, disposable lab-only `KS_PASS` for PKCS#12 fixtures. **Never commit or paste the password.**

## Quick start (clean checkout)

```bash
git clone https://github.com/Varun-CHINTHANIPPU/TLSpectre.git
cd TLSpectre
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
# Set JAVA_HOME to your installed JDK 27 and add $JAVA_HOME/bin to PATH.
java -version
mvn -version
make build
make bench
# Set a new private lab password for your local test fixtures:
read -rsp 'Lab-only PKCS12 password: ' KS_PASS; echo
export KS_PASS
make pki
make test
make test-java
python scripts/check_tracked_secrets.py
```

Functional smoke test: in one terminal run `make server CONFIG=configs/server/P1.yaml`; in another terminal, with the same virtualenv and `KS_PASS`, run `make probe CONFIG=configs/server/P1.yaml`. For a bounded E1 pilot, install optional probe tools and run `PYTHONPATH=harness python -m tlslab.run_experiment E1 --run --pilot`. Pilots are **not** substitutes for full measurement campaigns.

CI (`.github/workflows/ci.yml`) builds and tests Python/Java, generates disposable PKI, and exercises bounded integration/research pilots. Full E1–E7 datasets are **not** rerun by CI; some full campaigns require controlled laptop hardware, root isolation and hours of measurement.

## Reproduce experiments and audit results

```bash
export PYTHONPATH="$PWD/harness"
# Inspect the frozen experimental factor plan without executing:
python -m tlslab.run_experiment E4
# Execute a bounded pilot:
python -m tlslab.run_experiment E4 --run --pilot
# Full E1 campaign (requires the configured lab, tools and services):
python -m tlslab.run_experiment E1 --run
python scripts/report_e1.py <E1-run-directory> --out results/reports/E1-full-audit.json
# E2–E6: select the exact full non-pilot dataset when multiple exist:
python -m tlslab.analysis.audit_measurements --run E2=<E2-run-directory>
# E7: compare independently measured full main/reference runs:
python -m tlslab.analysis.audit_e7_reference --main <E7-main-dir> --reference <E7-reference-dir>
```

The angle-bracket paths above are placeholders; replace them with real local run paths. For full isolated E5–E7 procedures, CPU tuning, OCSP controls, and known limitations, see [experiment runbook](docs/EXPERIMENT_RUNBOOK.md) and [validation rules](docs/VALIDATION_RULES.md).

### Generate F1–F6 and T1–T7 from explicitly selected runs

The default unfiltered artifact loader may encounter old incomplete campaigns or concatenate multiple complete E2 runs. **Never delete or silently pool them.** The reusable exporter creates a temporary symlink view containing only explicitly selected datasets and runs the *existing strict evidence gates*.

```bash
# This example file contains the operator's November 20 local run IDs.
# After a fresh checkout or new campaign, edit a COPY to match your own paths.
cp configs/artifact-selection.example.json configs/artifact-selection.local.json
python scripts/generate_final_artifacts.py --selection configs/artifact-selection.local.json
```

On success it writes six PDFs to `results/figures/`, seven CSVs to `results/tables/`, and a local selection/provenance record to `results/reports/artifact-selection.json`. The original raw evidence remains untouched. All `data/raw/`, `data/references/`, `pki/out/`, `results/` and local selection files must remain private and untracked.

## Security and interpretation

- Do **not** publish private keys, PKCS#12 stores, OCSP signing keys, exported TLS traffic secrets, keylogs, unredacted packet captures, or real credentials.
- `scripts/check_tracked_secrets.py` scans currently tracked files for obvious private material; it is a **heuristic**, not a historical Git secret audit. Review `git status`, commit history and any external secret-scanning results before making a repository public.
- The figures and tables are useful implementation evidence, **not proof of an exploitable TLS vulnerability or independently verified performance superiority**.
- `docs/RESEARCH_VALIDATION_CHECKLIST.md` tracks further work required for publication-quality scientific claims.

This repository is suitable for studying and demonstrating applied TLS, protocol testing, cryptographic verification, hybrid key exchange, PKI policy, Linux network isolation, and reproducible benchmark engineering.
