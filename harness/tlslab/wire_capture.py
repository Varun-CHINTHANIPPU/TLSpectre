"""Independent on-the-wire evidence for E4 and E5, from plaintext TLS framing.

A pass-through TCP proxy stores both directions of every connection
byte-for-byte. Nothing is decrypted: TLS 1.3 ClientHello / ServerHello /
HelloRetryRequest and every record header are in clear text, which is enough
to verify, independently of the Java client's self-report:

* the negotiated named group (ServerHello key_share) and whether an HRR occurred
* that no PSK was offered or accepted (no session resumption)
* handshake byte counts per flight
* the ciphertext size of every application-data record (E4 record size)

The proxy is used only for separate, untimed verification connections, never
inside a timed measurement. Local lab addresses only.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import select
import statistics
import subprocess
import sys
import time

ALLOWED = ("127.0.0.1", "10.77.1.1")
HRR_RANDOM = hashlib.sha256(b"HelloRetryRequest").digest()
GROUPS = {0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
          0x001d: "x25519", 0x001e: "x448", 0x0100: "ffdhe2048", 0x0101: "ffdhe3072",
          0x11eb: "SecP256r1MLKEM768", 0x11ec: "X25519MLKEM768",
          0x11ed: "SecP384r1MLKEM1024"}
SUITES = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
          0x1303: "TLS_CHACHA20_POLY1305_SHA256"}
EXT_KEY_SHARE, EXT_PSK, EXT_EARLY_DATA, EXT_VERSIONS, EXT_GROUPS = 51, 41, 42, 43, 10
FULL_RECORD = 16384 + 1 + 16       # max plaintext + inner content type + AEAD tag


# ----------------------------------------------------------------- proxy ---

async def _pump(reader, writer, sink, times, direction, clock):
    offset = 0
    try:
        while data := await reader.read(65536):
            sink.write(data)
            times.write(json.dumps({"d": direction, "o": offset, "t": clock()}) + "\n")
            offset += len(data)
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        sink.flush()
        times.flush()
        try:
            writer.close()
        except Exception:
            pass


async def _serve(args):
    counter = {"n": 0}
    clock = time.monotonic

    async def handle(client_reader, client_writer):
        counter["n"] += 1
        stem = args.out / f"conn-{counter['n']:04d}"
        upstream_reader, upstream_writer = await asyncio.open_connection(
            args.upstream_host, args.upstream_port)
        with open(f"{stem}.c2s", "wb") as c2s, open(f"{stem}.s2c", "wb") as s2c, \
                open(f"{stem}.times.jsonl", "w") as times:
            await asyncio.gather(
                _pump(client_reader, upstream_writer, c2s, times, "c2s", clock),
                _pump(upstream_reader, client_writer, s2c, times, "s2c", clock))

    server = await asyncio.start_server(handle, args.listen_host, args.listen_port)
    async with server:
        print("TLSLAB_WIRE_CAPTURE_READY", flush=True)
        await server.serve_forever()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=9443)
    ap.add_argument("--upstream-host", required=True)
    ap.add_argument("--upstream-port", type=int, default=8443)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    if args.upstream_host not in ALLOWED or args.listen_host != "127.0.0.1":
        ap.error("local laboratory addresses only")
    args.out.mkdir(parents=True, exist_ok=True)
    asyncio.run(_serve(args))


@contextmanager
def wire_proxy(upstream_host: str, upstream_port: int, out: Path, *,
               namespace: str | None = None, listen_port: int = 9443):
    """Run the capture proxy (inside `namespace` if given); yield (host, port)."""
    from .netns import exec_in
    from .launch import ROOT
    out.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "tlslab.wire_capture", "--listen-port", str(listen_port),
           "--upstream-host", upstream_host, "--upstream-port", str(upstream_port),
           "--out", str(out)]
    if namespace:
        cmd = exec_in(namespace, cmd)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "harness") + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        line = b""
        while time.monotonic() < deadline and not line.endswith(b"\n"):
            if proc.poll() is not None:
                raise RuntimeError("wire capture proxy exited: " + proc.stderr.read().decode()[-400:])
            ready, _, _ = select.select([proc.stdout], [], [], 0.2)
            if ready:
                line += os.read(proc.stdout.fileno(), 64)
        if line.strip() != b"TLSLAB_WIRE_CAPTURE_READY":
            raise RuntimeError("wire capture proxy not ready: " + line.decode(errors="replace"))
        yield "127.0.0.1", listen_port
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        time.sleep(0.2)


# ---------------------------------------------------------------- parsing ---

def records(data: bytes) -> list[tuple[int, int, bytes]]:
    """(offset, content_type, payload) for every complete TLS record."""
    out, at = [], 0
    while at + 5 <= len(data):
        size = int.from_bytes(data[at + 3:at + 5], "big")
        if at + 5 + size > len(data):
            break
        out.append((at, data[at], data[at + 5:at + 5 + size]))
        at += 5 + size
    return out


def _extensions(blob: bytes) -> dict[int, bytes]:
    found, at = {}, 0
    while at + 4 <= len(blob):
        kind = int.from_bytes(blob[at:at + 2], "big")
        size = int.from_bytes(blob[at + 2:at + 4], "big")
        found[kind] = blob[at + 4:at + 4 + size]
        at += 4 + size
    return found


def _handshakes(recs) -> list[tuple[int, int, bytes]]:
    """(record offset, handshake type, body) from plaintext handshake records."""
    out, buffer, first = [], b"", None
    for offset, kind, payload in recs:
        if kind != 22:
            continue
        if not buffer:
            first = offset
        buffer += payload
        while len(buffer) >= 4 and len(buffer) >= 4 + int.from_bytes(buffer[1:4], "big"):
            size = int.from_bytes(buffer[1:4], "big")
            out.append((first, buffer[0], buffer[4:4 + size]))
            buffer = buffer[4 + size:]
            first = offset
    return out


def parse_client_hello(body: bytes) -> dict:
    at = 2 + 32
    at += 1 + body[at]                                    # session id
    suites = int.from_bytes(body[at:at + 2], "big")
    at += 2 + suites
    at += 1 + body[at]                                    # compression methods
    ext = _extensions(body[at + 2:at + 2 + int.from_bytes(body[at:at + 2], "big")])
    groups = ext.get(EXT_GROUPS, b"")[2:]
    shares, share_blob, i = [], ext.get(EXT_KEY_SHARE, b"")[2:], 0
    while i + 4 <= len(share_blob):
        shares.append(GROUPS.get(int.from_bytes(share_blob[i:i + 2], "big"),
                                 hex(int.from_bytes(share_blob[i:i + 2], "big"))))
        i += 4 + int.from_bytes(share_blob[i + 2:i + 4], "big")
    return {"offered_groups": [GROUPS.get(int.from_bytes(groups[j:j + 2], "big"),
                                          hex(int.from_bytes(groups[j:j + 2], "big")))
                               for j in range(0, len(groups) - 1, 2)],
            "key_share_groups": shares,
            "psk_offered": EXT_PSK in ext, "early_data_offered": EXT_EARLY_DATA in ext}


def parse_server_hello(body: bytes) -> dict:
    random = body[2:34]
    at = 34
    at += 1 + body[at]
    suite = int.from_bytes(body[at:at + 2], "big")
    at += 3                                               # suite + compression
    ext = _extensions(body[at + 2:at + 2 + int.from_bytes(body[at:at + 2], "big")])
    share = ext.get(EXT_KEY_SHARE, b"")
    group = int.from_bytes(share[:2], "big") if len(share) >= 2 else None
    version = ext.get(EXT_VERSIONS, b"")
    return {"hrr": random == HRR_RANDOM, "suite": SUITES.get(suite, hex(suite)),
            "group": GROUPS.get(group, hex(group)) if group is not None else None,
            "psk_accepted": EXT_PSK in ext,
            "tls13": version == b"\x03\x04"}


def _times(stem: Path):
    marks = {"c2s": [], "s2c": []}
    for line in Path(f"{stem}.times.jsonl").read_text().splitlines():
        entry = json.loads(line)
        marks[entry["d"]].append((entry["o"], entry["t"]))
    return marks


def _arrival(marks, offset):
    """Time the chunk containing byte `offset` was relayed."""
    best = None
    for start, when in marks:
        if start <= offset:
            best = when
    return best


def handshake_summary(stem: Path) -> dict:
    """Plaintext handshake facts for one captured connection."""
    c2s = Path(f"{stem}.c2s").read_bytes()
    s2c = Path(f"{stem}.s2c").read_bytes()
    marks = _times(stem)
    crec, srec = records(c2s), records(s2c)
    chellos = [(o, b) for o, t, b in _handshakes(crec) if t == 1]
    shellos = [(o, b) for o, t, b in _handshakes(srec) if t == 2]
    if not chellos or not shellos:
        raise ValueError("ClientHello or ServerHello missing from capture")
    first_ch = parse_client_hello(chellos[0][1])
    hellos = [parse_server_hello(b) for _, b in shellos]
    final = hellos[-1]
    last_ch_offset = chellos[-1][0]
    # Client second flight: records after the final ClientHello up to and
    # including its first encrypted record (Finished), plus any CCS.
    flight, finished_offset = [], None
    for offset, kind, payload in crec:
        if offset <= last_ch_offset:
            continue
        flight.append(5 + len(payload))
        if kind == 23:
            finished_offset = offset
            break
    finished_at = _arrival(marks["c2s"], finished_offset) if finished_offset is not None else None
    # Server flight: from the final ServerHello until the client's Finished.
    sh_offset = shellos[-1][0]
    server_flight = [(o, k, p) for o, k, p in srec if o >= sh_offset and (
        finished_at is None or (_arrival(marks["s2c"], o) or 0) <= finished_at)]
    sh_record = next(5 + len(p) for o, k, p in srec if o == sh_offset)
    return {
        "hrr": any(h["hrr"] for h in hellos),
        "negotiated_group": final["group"], "negotiated_suite": final["suite"],
        "tls13": final["tls13"], "psk_offered": first_ch["psk_offered"],
        "psk_accepted": final["psk_accepted"], "early_data_offered": first_ch["early_data_offered"],
        "client_key_share_groups": first_ch["key_share_groups"],
        "client_hello_bytes": sum(5 + len(b) for o, k, b in crec if o <= last_ch_offset),
        "server_hello_bytes": sh_record,
        "encrypted_server_bytes": sum(5 + len(p) for o, k, p in server_flight if k == 23),
        "server_flight_records": len(server_flight),
        "client_flight_bytes": sum(flight),
    }


def record_size_summary(stem: Path, *, minimum_body: int) -> dict:
    """Ciphertext sizes of server->client application-data records."""
    data = [len(p) for _, kind, p in records(Path(f"{stem}.s2c").read_bytes()) if kind == 23]
    total = sum(data)
    full = sum(n for n in data if n == FULL_RECORD)
    large = sum(n for n in data if n >= 16000)
    largest = max(data) if data else None
    summary = {"app_records": len(data), "app_ciphertext_bytes": total,
               "max_record_ciphertext": largest,
               "median_record_ciphertext": statistics.median(data) if data else None,
               "records_per_mib": len(data) / (total / 1048576) if total else None,
               "full_record_byte_fraction": full / total if total else None,
               "large_record_byte_fraction": large / total if total else None,
               "transfer_large_enough": total >= minimum_body,
               # RFC 9846 5.2: TLSCiphertext.length <= 2^14 + 256
               "rfc_record_limit_ok": largest is not None and largest <= 16384 + 256}
    summary["ok"] = bool(summary["transfer_large_enough"] and summary["rfc_record_limit_ok"]
                         and (summary["large_record_byte_fraction"] or 0) >= 0.95)
    return summary


def connections(folder: Path) -> list[Path]:
    return sorted(p.with_suffix("") for p in folder.glob("conn-*.c2s"))


if __name__ == "__main__":
    main()
