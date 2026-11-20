"""Independent published RFC 8448 example values, section 3 (simple 1-RTT)."""
from tlslab.keysched import derive_secret, hkdf_extract, record_key_iv


def test_rfc8448_simple_1rtt_early_and_derived_secrets():
    early = hkdf_extract(bytes(32), bytes(32), "sha256")
    assert early.hex() == (
        "33ad0a1c607ec03b09e6cd9893680ce2"
        "10adf300aa1f2660e1b22e10f170f92a"
    )
    assert derive_secret(early, "derived", b"", "sha256").hex() == (
        "6f2615a108c702c5678f54fc9dbab697"
        "16c076189c48250cebeac3576c3611ba"
    )


def test_rfc8448_server_handshake_record_key_and_iv():
    # RFC 8448 simple handshake, server write traffic keys.
    secret = bytes.fromhex(
        "8b02d3c00442a2722c4098ebe8675b23"
        "e801510f0d7ed778d8eb0b8f42a19a5e"
    )
    key, iv = record_key_iv(secret, "TLS_AES_128_GCM_SHA256")
    assert key.hex() == "6cb6e60619d8c7355c5d4c4bc2be90d5"
    assert iv.hex() == "64f239530c3b888fde85e0be"
