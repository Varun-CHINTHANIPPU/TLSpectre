# Controlled research runbook (draft)

## P1 vs A3: TLS version intervention

1. Install JDK 27, Maven, OpenSSL, Python (>=3.12).
2. `export KS_PASS='local-secret'`; `make build && make pki`.
3. In terminal A: `make server CONFIG=configs/server/P1.yaml`.
4. In terminal B: `make probe CONFIG=configs/server/P1.yaml` and store the JSON.
5. Stop server, restart with `CONFIG=configs/server/A3.yaml`. Probe A3.
6. Use `openssl s_client -tls1_2 -connect 127.0.0.1:8443 -servername lab.test -CAfile pki/out/ca.crt` to independently confirm the A3 contrast.

Do not compare timing while key logging or packet capture is running.

## HSTS and OCSP

- HSTS: P1 vs A2, check HTTPS `/health` and `/not-found`; no HSTS on HTTP.
- OCSP: run `make ocsp` in a separate terminal; examine `openssl s_client -status` output. A1 disables stapling.
- Must-Staple: use `pki/out/srv_muststaple.p12` explicitly in the YAML for that scenario. **Must-Staple is not a server-side enforcement policy**. The Java revocation client, responder interruption and validation matrix remain to be implemented.
- Never treat a missing staple, unreachable responder, certificate validation error and expired response as interchangeable outcomes.

## Classical versus hybrid handshake exploration

Use the Java handshake client **after building**:

```bash
java -cp java/target/tlslab-server.jar lab.tls13.client.HandshakeClient \
  127.0.0.1 8443 lab.test SunJSSE X25519MLKEM768 30 pki/out/truststore.p12 > handshake.csv
```

The output columns `negotiated_group` and `resumption` deliberately read `UNVERIFIED`. Verify a separate captured handshake's `key_share` and `pre_shared_key` fields before interpreting these numbers as specific-group full-handshake timings. These are exploratory timings, not E5 research results.

## Java client revocation policy exploration

See [E6 policies](E6_CLIENT_POLICIES.md) for explicitly limited K1–K4 validation and an intentional revocation scenario.

## JMH AES/ChaCha exploration

```bash
mvn -f java/bench/pom.xml -B -ntp package
java -jar java/bench/target/benchmarks.jar -rf json -rff aead-local.json
```

This is a primitive throughput benchmark (not TLS record throughput). Preserve provider and JVM flags in your manifest. Run separate fork groups for intrinsic ablations; do not compare BC provider with SunJCE as if provider selection alone identified the complete TLS implementation.

## E4 TLS record-level bulk goodput

See [C3 E4 bulk client](E4_BULK_CLIENT.md). The server now supports 512 MiB streamed transfers using six single-suite E4 profiles. One client invocation gives one CSV row; it **does not** produce the study's 20-block E4 results.
