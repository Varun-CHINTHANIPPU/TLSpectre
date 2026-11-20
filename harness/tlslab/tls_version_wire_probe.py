"""PR03: independently test absence of supported_versions on a TLS 1.3-only server.

The original upstream tlsfuzzer test has 269 conversations, most about
draft-version/TLS 1.2 fallback and an RSA-only sanity handshake. PR03's
specified question is narrower: can a modern TLS 1.3-only endpoint correctly
reject a syntactically valid legacy ClientHello lacking supported_versions?

This module uses an independently constructed TLS record and validates the
mutant's extension vector before sending. It neither rewrites tlsfuzzer
counts nor claims the upstream suite passed.
RFC 9846, section 4.2.1 requires fatal protocol_version when a server only
supports versions greater than ClientHello.legacy_version (0x0303).
"""
from __future__ import annotations

from .tls13_wire_probe import build_client_hello, first_server_message


def client_hello_extension_types(record: bytes) -> list[int]:
    """Parse and length-check ClientHello extensions from a single TLS record."""
    if len(record) < 9 or record[0] != 22 or record[5] != 1:
        raise ValueError("Not a TLS ClientHello record")
    if int.from_bytes(record[3:5], "big") != len(record) - 5:
        raise ValueError("TLS record length mismatch")
    if int.from_bytes(record[6:9], "big") != len(record) - 9:
        raise ValueError("ClientHello handshake length mismatch")
    end = len(record)
    pos = 9 + 2 + 32             # legacy_version and client_random
    if pos >= end:
        raise ValueError("Truncated session ID")
    session_length = record[pos]
    pos += 1 + session_length
    if pos + 2 > end:
        raise ValueError("Truncated cipher suites")
    suite_len = int.from_bytes(record[pos:pos+2], "big")
    if suite_len == 0 or suite_len % 2:
        raise ValueError("Invalid cipher suite vector")
    pos += 2 + suite_len
    if pos >= end:
        raise ValueError("Truncated compression methods")
    compression_len = record[pos]
    pos += 1 + compression_len
    if pos + 2 > end:
        raise ValueError("Truncated extensions length")
    extensions_len = int.from_bytes(record[pos:pos+2], "big")
    pos += 2
    if pos + extensions_len != end:
        raise ValueError("Extensions vector length mismatch")
    ids = []
    while pos < end:
        if pos + 4 > end:
            raise ValueError("Truncated extension header")
        kind = int.from_bytes(record[pos:pos+2], "big")
        size = int.from_bytes(record[pos+2:pos+4], "big")
        pos += 4 + size
        if pos > end:
            raise ValueError("Truncated extension body")
        ids.append(kind)
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate ClientHello extensions")
    return ids


def probe(host: str = "127.0.0.1", port: int = 8443) -> dict:
    """Return PR03-specific PASS/FAIL/INCONCLUSIVE plus both raw-wire replies.

    Only use this as a TLS 1.3-only profile oracle. With TLS 1.2 enabled, a
    no-supported_versions ClientHello can legitimately negotiate TLS 1.2.
    """
    control = build_client_hello(b"\x00", supported_versions=True,
                                 offer_tls12_cipher=True)
    mutant = build_client_hello(b"\x00", supported_versions=False,
                                offer_tls12_cipher=True)
    control_extensions = client_hello_extension_types(control)
    mutant_extensions = client_hello_extension_types(mutant)
    if 43 not in control_extensions or 43 in mutant_extensions:
        raise ValueError("Version-negotiation oracle failed to construct a valid mutation")
    # Control and mutant both advertise a real TLS 1.2 ECDHE-ECDSA cipher and
    # a real X25519 key share, so rejection cannot simply be blamed on a
    # TLS 1.3-only cipher list.
    baseline = first_server_message(host, port, b"\x00", hello=control)
    no_ext = first_server_message(host, port, b"\x00", hello=mutant)
    if baseline["response"] != "server_hello":
        verdict = "INCONCLUSIVE"
        reason = "Valid TLS 1.3 ClientHello control did not receive ServerHello"
    elif no_ext["response"] == "server_hello":
        verdict = "FAIL"
        reason = "ServerHello after ClientHello without supported_versions on TLS 1.3-only endpoint"
    elif (no_ext["response"] == "alert"
          and no_ext.get("alert_level") == 2
          and no_ext.get("alert") == "protocol_version"):
        verdict = "PASS"
        reason = "No-supported_versions ClientHello received required fatal protocol_version alert"
    else:
        verdict = "INCONCLUSIVE"
        reason = "No TLS 1.3 negotiation observed, but required fatal protocol_version alert not established"
    return {
        "verdict": verdict,
        "reason": reason,
        "control": baseline,
        "without_supported_versions": no_ext,
        "control_extension_types": control_extensions,
        "mutant_extension_types": mutant_extensions,
        "offered_tls12_cipher": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "scope": "RFC 9846 section 4.2.1 TLS 1.3-only version negotiation",
    }
