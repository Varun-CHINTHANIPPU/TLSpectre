"""Independent TLS 1.3 compression probe, using Python sockets + cryptography.

Observes the first server handshake or alert, not handshake completion.
Only loopback and the isolated lab server are permitted. RFC 9846 §4.2.2.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ALLOWED = ("127.0.0.1", "localhost", "10.77.1.1")
ALERTS = {10: "unexpected_message", 20: "bad_record_mac", 22: "record_overflow",
          40: "handshake_failure", 47: "illegal_parameter", 50: "decode_error",
          70: "protocol_version", 80: "internal_error"}


def _u16(value: int) -> bytes:
    return struct.pack("!H", value)


def _extension(kind: int, data: bytes) -> bytes:
    return _u16(kind) + _u16(len(data)) + data


def build_client_hello(compression: bytes, server_name: str = "lab.test", *,
                       supported_versions: bool = True,
                       offer_tls12_cipher: bool = False) -> bytes:
    """Build a well-formed ClientHello; optional PR03 omission is deliberate.

    The TLS 1.2 cipher keeps the no-supported_versions variant a plausible
    legacy ClientHello rather than an offer with *only* TLS 1.3 cipher IDs.
    """
    if not 1 <= len(compression) <= 255:
        raise ValueError("compression vector length must be 1..255")
    hostname = server_name.encode("ascii")
    if not 1 <= len(hostname) <= 253:
        raise ValueError("invalid SNI hostname length")
    key = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    share = _u16(29) + _u16(len(key)) + key
    name = b"\x00" + _u16(len(hostname)) + hostname
    extensions = b"".join((
        _extension(0, _u16(len(name)) + name),       # SNI
        *([_extension(43, b"\x02\x03\x04")] if supported_versions else []),
        _extension(10, b"\x00\x02\x00\x1d"),     # supported_groups: x25519
        _extension(13, b"\x00\x04\x04\x03\x08\x04"),  # signature_algorithms
        _extension(51, _u16(len(share)) + share),   # key_share
    ))
    suites = b"\x13\x01\x13\x02" + (b"\xc0\x2b" if offer_tls12_cipher else b"")
    body = (
        b"\x03\x03" + os.urandom(32) + b"\x00"
        + _u16(len(suites)) + suites
        + bytes((len(compression),)) + compression
        + _u16(len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + _u16(len(handshake)) + handshake


def compression_from_hello(record: bytes) -> bytes:
    """Decode the exact compression vector transmitted on the wire."""
    if len(record) < 9 or record[:3] != b"\x16\x03\x01":
        raise ValueError("invalid handshake record")
    if int.from_bytes(record[3:5], "big") != len(record) - 5 or record[5] != 1:
        raise ValueError("inconsistent TLS record length or message type")
    if int.from_bytes(record[6:9], "big") != len(record) - 9:
        raise ValueError("inconsistent ClientHello length")
    offset = 9 + 2 + 32
    offset += 1 + record[offset]
    offset += 2 + int.from_bytes(record[offset:offset + 2], "big")
    if offset >= len(record):
        raise ValueError("missing compression vector")
    n = record[offset]
    result = record[offset + 1:offset + 1 + n]
    if len(result) != n:
        raise ValueError("truncated compression vector")
    return result


def _read_exact(connection: socket.socket, count: int) -> bytes:
    out = bytearray()
    while len(out) < count:
        chunk = connection.recv(count - len(out))
        if not chunk:
            break
        out.extend(chunk)
    return bytes(out)


def first_server_message(host: str, port: int, compression: bytes, timeout: float = 5,
                         *, hello: bytes | None = None) -> dict:
    if host not in ALLOWED or not 1 <= port <= 65535:
        raise ValueError("only local laboratory endpoints allowed")
    hello = build_client_hello(compression) if hello is None else hello
    if compression_from_hello(hello) != compression:
        raise ValueError("ClientHello compression vector differs from requested value")
    evidence = {"sent_compression_hex": compression.hex()}
    try:
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(hello)
            for _ in range(5):
                header = _read_exact(connection, 5)
                if len(header) != 5:
                    return {**evidence, "response": "closed"}
                length = int.from_bytes(header[3:5], "big")
                if length > 16640:
                    return {**evidence, "response": "oversized"}
                body = _read_exact(connection, length)
                if len(body) != length:
                    return {**evidence, "response": "truncated"}
                if header[0] == 20:  # compatibility ChangeCipherSpec
                    continue
                if header[0] == 21 and len(body) >= 2:
                    return {**evidence, "response": "alert",
                            "alert_level": body[0],
                            "alert": ALERTS.get(body[1], f"alert_{body[1]}")}
                if header[0] == 22 and len(body) >= 4:
                    return {**evidence, "response": "server_hello" if body[0] == 2
                            else f"handshake_{body[0]}"}
                return {**evidence, "response": f"record_{header[0]}"}
            return {**evidence, "response": "no_decision"}
    except (OSError, TimeoutError) as exc:
        return {**evidence, "response": "transport_error",
                "error": type(exc).__name__}


def probe(host: str = "127.0.0.1", port: int = 8443) -> dict:
    """Independent oracle: valid null vs non-null compression ClientHellos."""
    observations = {
        "baseline": first_server_message(host, port, b"\x00"),
        "deflate_and_null": first_server_message(host, port, b"\x01\x00"),
        "deflate_only": first_server_message(host, port, b"\x01"),
    }
    baseline = observations["baseline"]
    invalid = [observations["deflate_and_null"], observations["deflate_only"]]
    if baseline["response"] != "server_hello":
        verdict = "INCONCLUSIVE"
        reason = "Unmodified TLS 1.3 ClientHello did not elicit ServerHello"
    elif any(case["response"] == "server_hello" for case in invalid):
        verdict = "FAIL"
        reason = "ServerHello received for invalid TLS 1.3 compression offer"
    elif all(case["response"] == "alert" and case.get("alert") == "illegal_parameter"
             and case.get("alert_level") == 2 for case in invalid):
        verdict = "PASS"
        reason = "Both invalid compression offers rejected with fatal illegal_parameter"
    else:
        verdict = "INCONCLUSIVE"
        reason = "Invalid offer not accepted, but required alert was not established"
    return {"verdict": verdict, "reason": reason, "cases": observations,
            "standard": "RFC 9846 section 4.2.2"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", choices=ALLOWED, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    print(json.dumps(probe(args.host, args.port), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
