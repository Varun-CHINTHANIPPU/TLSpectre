"""RFC 8446 TLS 1.3 trace verification from reassembled TCP record bytes.

NSS key-log secrets are REQUIRED. The live check independently recomputes
record AEAD tags and both Finished MACs downstream from exported secrets.
It does not re-derive (EC)DHE or ML-KEM shared secrets from live captures.
"""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from ..keysched import SUITES, decrypt_record, verify_finished


class TraceError(ValueError):
    pass


@dataclass(frozen=True)
class Record:
    direction: str
    timestamp: float
    data: bytes


def keylog(path: Path) -> dict[str, dict[str, bytes]]:
    entries = defaultdict(dict)
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        if len(tokens) != 3:
            raise TraceError(f"malformed keylog line {lineno}")
        label, client_random, hex_secret = tokens
        try:
            if len(client_random) != 64:
                raise ValueError()
            bytes.fromhex(client_random)
            secret = bytes.fromhex(hex_secret)
        except ValueError:
            raise TraceError(f"bad hex keylog line {lineno}") from None
        if not secret:
            raise TraceError(f"empty secret at line {lineno}")
        prev = entries[client_random.lower()].get(label)
        if prev is not None and prev != secret:
            raise TraceError("conflicting secret for client random/label")
        entries[client_random.lower()][label] = secret
    return dict(entries)


def parse_tls_records(chunks: list[tuple[int, float, bytes]], direction: str) -> list[Record]:
    """Reassemble one TCP direction, deduplicate retransmits, and reject gaps.

    Chunks are tuples (relative tcp.seq, frame.time_epoch, TCP payload).
    Missing or inconsistent TCP bytes invalidate the run, not a PASS.
    """
    if not chunks:
        raise TraceError("empty TCP direction")
    chunks = sorted(chunks, key=lambda p: (p[0], p[1]))
    start = chunks[0][0]
    next_seq = start
    buffer = bytearray()
    result = []
    for seq, when, data in chunks:
        if seq > next_seq:
            raise TraceError(f"TCP gap: expected {next_seq}, received {seq}")
        skip = next_seq - seq
        if skip >= len(data):
            continue
        new = data[skip:]
        next_seq += len(new)
        buffer.extend(new)
        while len(buffer) >= 5:
            length = int.from_bytes(buffer[3:5], "big")
            if length > 16640:
                raise TraceError("invalid TLS record length")
            if len(buffer) < 5 + length:
                break
            record = bytes(buffer[:5 + length])
            del buffer[:5 + length]
            result.append(Record(direction, when, record))
    if buffer:
        raise TraceError(f"truncated TLS record tail: {len(buffer)} bytes")
    return result


def parse_handshake_messages(buffer: bytearray, data: bytes):
    buffer.extend(data)
    items = []
    while len(buffer) >= 4:
        size = int.from_bytes(buffer[1:4], "big")
        if size > 1 << 20:
            raise TraceError("unexpected >1 MiB handshake message")
        if len(buffer) < 4 + size:
            break
        message = bytes(buffer[:4 + size])
        del buffer[:4 + size]
        items.append(message)
    return items


def client_hello_random(records: list[Record]) -> str:
    for record in records:
        if record.data[0] != 22:
            continue
        raw = record.data[5:]
        if len(raw) >= 4 + 2 + 32 and raw[0] == 1:
            return raw[6:38].hex()
    raise TraceError("ClientHello.random not found (capture starts too late)")


def negotiated_suite(records: list[Record]) -> str:
    # ServerHello body: legacy_version(2) + random(32) + session-id vector(1+n)
    # + cipher_suite(2). Suites are TLS1.3 IDs 0x1301..0x1303.
    mapping = {0x1301: "TLS_AES_128_GCM_SHA256",
               0x1302: "TLS_AES_256_GCM_SHA384",
               0x1303: "TLS_CHACHA20_POLY1305_SHA256"}
    for record in records:
        if record.data[0] != 22:
            continue
        data = record.data[5:]
        if len(data) >= 4 + 2 + 32 + 1 + 2 and data[0] == 2:
            body = data[4:]
            sid_len = body[34]
            offset = 35 + sid_len
            if offset + 2 > len(body):
                raise TraceError("truncated ServerHello suite")
            selected = int.from_bytes(body[offset:offset + 2], "big")
            if selected not in mapping:
                raise TraceError(f"unknown TLS 1.3 suite: {selected:#x}")
            return mapping[selected]
    raise TraceError("ServerHello not found")


def verify_records(records: list[Record], key_secrets: dict[str, bytes], suite: str):
    if suite not in SUITES:
        raise TraceError("unsupported cipher")
    hash_name = SUITES[suite][0]
    required = {
        "client_hs": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "server_hs": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "client_app": "CLIENT_TRAFFIC_SECRET_0",
        "server_app": "SERVER_TRAFFIC_SECRET_0",
    }
    missing = [v for v in required.values() if v not in key_secrets]
    if missing:
        raise TraceError("missing keylog entries: " + ",".join(missing))
    for label in required.values():
        expected = 32 if hash_name == "sha256" else 48
        if len(key_secrets[label]) != expected:
            raise TraceError(f"bad {label} secret size")
    counters = {("client", "hs"): 0, ("server", "hs"): 0,
                ("client", "app"): 0, ("server", "app"): 0}
    epoch = {"client": "hs", "server": "hs"}
    buffers = {"client": bytearray(), "server": bytearray()}
    transcript = bytearray()
    finished = {"client": 0, "server": 0}
    verified_records = 0
    app_records = 0
    handshakes = 0

    def process_handshake(sender: str, msg: bytes):
        nonlocal handshakes
        typ = msg[0]
        if typ == 20 and epoch[sender] == "hs":
            if not verify_finished(key_secrets[required[sender + "_hs"]],
                                   bytes(transcript), msg[4:], hash_name):
                raise TraceError(f"{sender} Finished MAC failed")
            finished[sender] += 1
            epoch[sender] = "app"
        transcript.extend(msg)
        handshakes += 1

    for record in sorted(records, key=lambda r: r.timestamp):
        raw = record.data
        typ = raw[0]
        if typ == 20:  # middlebox compatibility CCS
            if raw != b"\x14\x03\x03\x00\x01\x01":
                raise TraceError("invalid plaintext change_cipher_spec")
            continue
        if typ == 22:
            for msg in parse_handshake_messages(buffers[record.direction], raw[5:]):
                process_handshake(record.direction, msg)
            continue
        if typ != 23:
            raise TraceError(f"unexpected TLS record outer type {typ}")
        sender = record.direction
        stage = epoch[sender]
        label = required[sender + "_" + stage]
        seq = counters[sender, stage]
        try:
            inner_type, plain = decrypt_record(raw, key_secrets[label], suite, seq)
        except Exception as exc:
            raise TraceError(f"AEAD decrypt/tag failed for {sender}, {stage}, seq={seq}: {type(exc).__name__}") from exc
        counters[sender, stage] += 1
        verified_records += 1
        if inner_type == 22:
            for msg in parse_handshake_messages(buffers[sender], plain):
                process_handshake(sender, msg)
        elif inner_type == 23:
            app_records += 1
        elif inner_type not in (20, 21):
            raise TraceError(f"unexpected TLS inner type {inner_type}")
    if buffers["client"] or buffers["server"]:
        raise TraceError("truncated handshake message tail")
    if finished != {"client": 1, "server": 1}:
        raise TraceError(f"incomplete Finished verification: {finished}")
    if verified_records == 0:
        raise TraceError("no encrypted records verified")
    return {"status": "PASS", "suite": suite, "finished": finished,
            "verified_aead_records": verified_records, "application_records": app_records,
            "handshake_messages": handshakes,
            "coverage": "traffic secrets -> AEAD/Finished only; not full (EC)DHE/ML-KEM re-derivation"}
