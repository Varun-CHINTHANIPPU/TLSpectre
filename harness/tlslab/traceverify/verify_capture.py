"""pcapng + NSS keylog validation with tshark TCP stream extraction.

Requires a complete TCP capture that contains handshake and application TLS
records. Supports ordinary 1-RTT handshakes only; HRR and post-handshake
KeyUpdate require a separate explicit parser, never count as PASS.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import subprocess
import sys

from .trace import Record, TraceError, keylog, parse_tls_records, client_hello_random, negotiated_suite, verify_records


def negotiated_group(records) -> str | None:
    """Group from the plaintext ServerHello key_share (HRR flagged as such)."""
    from ..wire_capture import parse_server_hello
    for record in records:
        data = record.data
        if record.direction == "server" and data[0] == 22 and len(data) > 9 and data[5] == 2:
            hello = parse_server_hello(data[9:9 + int.from_bytes(data[6:9], "big")])
            if not hello["hrr"]:
                return hello["group"]
    return None


def tshark_streams(pcap: Path):
    cmd = [
        "tshark", "-r", str(pcap), "-Y", "tcp.len > 0",
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
        "-e", "frame.time_epoch", "-e", "tcp.stream",
        "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport",
        "-e", "tcp.seq", "-e", "tcp.payload",
    ]
    try:
        run = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=90)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise TraceError(f"tshark failed: {type(exc).__name__}") from exc
    streams = defaultdict(lambda: defaultdict(list))
    for line in run.stdout.splitlines():
        tokens = line.split("\t")
        if len(tokens) != 8 or not tokens[-1]:
            continue
        when, stream, src, sport, dst, dport, sequence, payload = tokens
        try:
            direction = f"{src}:{sport}->{dst}:{dport}"
            streams[int(stream)][direction].append(
                (int(sequence), float(when), bytes.fromhex(payload.replace(":", ""))))
        except ValueError as exc:
            raise TraceError("invalid tshark TCP export fields") from exc
    return streams


def verify_capture(pcap: Path, key_path: Path, stream_index: int | None = None):
    keys = keylog(key_path)
    streams = tshark_streams(pcap)
    findings = []
    for idx, directions in streams.items():
        if stream_index is not None and stream_index != idx:
            continue
        if len(directions) != 2:
            continue
        directional = {}
        for source, chunks in directions.items():
            directional[source] = parse_tls_records(chunks, source)
        source_with_hello = [
            name for name, records in directional.items()
            if any(r.data[0] == 22 and len(r.data) >= 11 and r.data[5] == 1 for r in records)
        ]
        if len(source_with_hello) != 1:
            continue  # not a supported full TLS handshake
        client_source = source_with_hello[0]
        records = [
            Record("client" if source == client_source else "server", record.timestamp, record.data)
            for source, group in directional.items() for record in group
        ]
        random = client_hello_random(records)
        suite = negotiated_suite(records)
        group = negotiated_group(records)
        if random not in keys:
            findings.append({"tcp_stream": idx, "status": "FAIL", "error": "client_random absent in keylog"})
            continue
        try:
            checked = verify_records(records, keys[random], suite)
            checked["tcp_stream"] = idx
            checked["client_random"] = random
            checked["negotiated_group"] = group
            findings.append(checked)
        except TraceError as exc:
            findings.append({"tcp_stream": idx, "status": "FAIL", "error": str(exc)})
    if stream_index is not None and not findings:
        raise TraceError("Requested stream does not have a full supported 1-RTT ClientHello")
    if not findings:
        raise TraceError("No complete TLS 1.3 streams with ClientHello found")
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    parser.add_argument("keylog", type=Path)
    parser.add_argument("--stream", type=int)
    parser.add_argument("--out", type=Path)
    ns = parser.parse_args()
    try:
        rows = verify_capture(ns.capture, ns.keylog, ns.stream)
    except TraceError as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)}))
        return 2
    output = {"status": "PASS" if all(r["status"] == "PASS" for r in rows) else "FAILED",
              "streams": rows}
    if ns.out:
        ns.out.parent.mkdir(parents=True, exist_ok=True)
        ns.out.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output, indent=2))
    return 0 if output["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
