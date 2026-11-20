# Design corrections

Implementation-level corrections to the original research design. Research hypotheses remain hypotheses.

## Critical design corrections

1. **Separate TLS version controls (HC1):** Global `jdk.tls.disabledAlgorithms` cannot disable TLS 1.2 during A3/B2 experiments. Use `conf/hardened.security` for hardened TLS 1.3-only configurations; `conf/dual_stack.security` for A3/B2; no additional override for vendor baseline B1. Verify each with an external client.
2. **Named groups (HC3):** P1 is `[X25519MLKEM768, x25519, secp256r1]`. `SecP256r1MLKEM768` is **not** part of this default hardening policy, but E2/E5 can use an explicit alternative configuration. Do not silently treat that alternative as the same intervention.
3. **OCSP semantics (HC6/HC7):** A server supplying an OCSP response is not sufficient to prevent a revoked certificate being accepted. Separate *staple availability*, *certificate status*, *client policy*, *Must-Staple enforcement*, and *blocked responder access*. Java, curl and OpenSSL clients may differ. Treat unsupported provider features as N/A, not successes.
4. **Replay terminology:** Rejecting duplicate TLS records demonstrates record authentication/sequence checks, not general HTTP replay protection. TLS 1.3 does not provide general application replay resistance; 0-RTT is a special case. Retain a disabled-0-RTT hypothesis but verify independently.
5. **Finished verification:** A captured NSS traffic secret can check TLS 1.3 AEAD decryption and Finished MACs, but cannot independently establish correctness of the **upstream key exchange**. Validate that chain against RFC 8448 vectors separately and explicitly describe which layers were independently recomputed.
6. **Handshake resumption:** Never hardcode `resumed=false`. Fresh independent SSLContexts reduce resumption contamination, but a capture without `pre_shared_key` is necessary to certify full handshakes.
7. **Record proxy:** TLS outer application_data type 23 also wraps encrypted handshake records. Select record targets from a separate calibrated capture; timeouts and generic closes are distinct from authenticated fatal alerts. Never label all record replay tests as protection from application replay.
8. **Redirect/HSTS:** Jetty's default secure redirect is 302. Use 308 explicitly. Configure HSTS using `SecureRequestCustomizer` so secure error responses are covered, with no HSTS on plain HTTP.
9. **Causal scope:** Ablations A1/A2/A3/A4/A5/A6 do not isolate all 12 HCs. Report causal effects only for controls actually isolated by appropriate ablations; others remain configuration verification.
10. **Provider isolation:** A BCJSSE test does not automatically identify primitive implementation cost. Record selected TLS and JCE providers, and separate AEAD microbenchmarks by explicit primitive provider. Confirm BCJSSE named-group and stapling behavior with negotiated traces.
11. **Timing design:** Resolve P-cores from actual Linux topology, not guessed CPU IDs; do not persist governor/turbo changes without a trap-based restoration. Keep capture/agent off during timed runs; measure cold vs warm stapling after clean restarts.
12. **Unimplemented work:** E1 full probe matrix, E2 end-to-end capture verification, E3/E4 JMH and record benchmarks, E5 block-randomized hybrid timing, E6 24-by-5 revocation matrix, E7 stapling overhead, and full statistical output require subsequent implementation and hardware validation. No result is asserted.

## Official specifications/references

- RFC 8446: https://www.rfc-editor.org/rfc/rfc8446
- RFC 8448: https://www.rfc-editor.org/rfc/rfc8448
- RFC 10024: https://www.rfc-editor.org/rfc/rfc10024
- RFC 7633 (TLS Feature/Must-Staple): https://www.rfc-editor.org/rfc/rfc7633
- Oracle JDK 27 JSSE guide: https://docs.oracle.com/en/java/javase/27/security/java-secure-socket-extension-jsse-reference-guide.html
- Jetty 12.1 server API: https://javadoc.jetty.org/jetty-12.1/
