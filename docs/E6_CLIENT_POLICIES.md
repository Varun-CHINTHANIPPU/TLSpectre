# E6 client policy correction

The original 28-page research design defines exactly:

- K1: curl --cert-status (requires a stapled OCSP response).
- K2: Java PKIX hard-fail.
- K3: Java PKIX soft-fail.
- K4: Java default trust manager, revocation checking disabled.
- K5: Python ssl with VERIFY_CRL_CHECK_LEAF and trusted local CRL.

Optional K6 in Java is a laboratory-specific Must-Staple check layered on hard-fail PKIX; it is NOT an original E6 policy.

Use `harness/tlslab/revocation.py` to execute K1-K5 on an already prepared scenario. The complete 24-scenario setup requires separate certificate/responder manipulation and must not be inferred from these five client wrappers.
