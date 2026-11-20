# C3 bulk-throughput client for E4

This implementation covers the **missing bulk-transfer Java client** and a bounded-memory
server response path. It does **not** constitute the full E4 experimental study.

## Contract matching research design §12 E4

- Single HTTPS connection per run; HTTP/1.1 GET `/bytes/536870912`.
- TLS 1.3 pinned to exactly one suite; compare negotiated suite to requested suite.
- Classical `x25519` fixed in the six E4 profiles to avoid mixing in PQ handshake cost; verify negotiation by a separate capture.
- Java PKCS12 trust store with hostname verification (SNI `lab.test`).
- Require 200, exactly 512 MiB `Content-Length`, no chunked/content-compressed response.
- First 64 MiB transferred before starting the measurement clocks.
- Record wall-time and **client-process** CPU nanoseconds for the remaining 448 MiB.
- Output a one-row CSV with total/warmup/measured bytes, handshake latency, measured
  wall time, client CPU time, goodput (MiB/s) and client CPU ns/B.
- Server responds via serialized <= 16 KiB asynchronous HTTP writes from a static
  deterministic pattern, never a 512 MiB heap allocation. **This does not ensure**
  16 KiB TLS ciphertext records: validate record lengths in a separate capture.

## Commands

Requires JDK 27, Maven, OpenSSL, and local PKI from `make pki`.

```bash
export KS_PASS='choose-a-lab-only-password'
make build
make pki

# Terminal 1: P1 with only AES-128-GCM and a streamed 512 MiB response
make server CONFIG=configs/server/E4-P1-AES128.yaml

# Terminal 2: one client connection (the file is not automatically committed)
java -cp java/target/tlslab-server.jar lab.tls13.client.BulkClient \
  127.0.0.1 8443 lab.test SunJSSE TLS_AES_128_GCM_SHA256 \
  536870912 67108864 pki/out/truststore.p12 > e4-aes128-local.csv
```

Other prepared server profiles: `E4-P1-AES256`, `E4-P1-CHACHA`,
`E4-P2-AES128`, `E4-P2-AES256`, and `E4-P2-CHACHA`.
Stop the previous server before launching a new profile. Match
the client `provider` and `suite` arguments to the selected profile.

For quick functional validation without 512 MiB of network traffic:

```bash
# Run any E4 profile (maxPayloadBytes: 536870912), then request just 1 MiB
java -cp java/target/tlslab-server.jar lab.tls13.client.BulkClient \
  127.0.0.1 8443 lab.test SunJSSE TLS_AES_128_GCM_SHA256 \
  1048576 262144 pki/out/truststore.p12
```

Build and run the Java unit tests with `mvn -f java/pom.xml test`.

## Interpretation limitations

These are **per-connection exploratory metrics**, not the original E4 results.
The E4 protocol still requires the A4/A5 intrinsic variants, 20 randomized
complete 12-condition blocks, pinning/thermal controls, server CPU measurement,
noise isolation, Parquet output and paired statistical analysis. Client CPU ns/B
must not be substituted for server CPU ns/B. The JVM's process CPU clock includes
other JVM work. Timing excludes the warmup download, header parsing and final
end-of-stream validation, but includes TLS decryption and body reads on the
measurement phase.

The server's fixed 16 KiB `Response.write` buffers may be combined/split by TLS
providers. To establish the actual record size and suite, use a separate packet
capture **outside** timing runs. Do not enable key-log agents during the timed run.
