"""Calibrated TLS record mutation proxy for local lab use only.

The 1-based --index counts every client-to-server TLS outer record of type 23,
including encrypted handshake traffic. Do not infer application-data boundaries
or expected alerts from the type alone. Select an index from a separate capture.
"""
import argparse
import asyncio
from pathlib import Path


async def read_record(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(5)
    size = int.from_bytes(header[3:5], "big")
    if size > 16640:
        raise ValueError("oversized TLS record")
    return header + await reader.readexactly(size)


def mutate(record: bytes, action: str) -> bytes:
    if not record or len(record) < 6:
        raise ValueError("invalid record")
    if action == "bitflip":
        return record[:-1] + bytes([record[-1] ^ 1])
    if action == "truncate":
        return record[:5] + record[5:len(record) // 2]
    if action == "duplicate":
        return record + record
    if action == "drop":
        return b""
    if action == "passthrough":
        return record
    raise ValueError("unknown action")


async def forward_raw(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def handle_client(client_reader, client_writer, host: str, port: int,
                        action: str, index: int, capture_client: Path | None = None):
    upstream_reader, upstream_writer = await asyncio.open_connection(host, port)

    async def client_to_server():
        seen = 0
        capture = capture_client.open("wb") if capture_client is not None else None
        try:
            while True:
                record = await read_record(client_reader)
                if capture is not None:
                    capture.write(record)
                    capture.flush()
                if record[0] == 23:
                    seen += 1
                    if seen == index:
                        record = mutate(record, action)
                if record:
                    upstream_writer.write(record)
                    await upstream_writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            if capture is not None:
                capture.close()
            upstream_writer.close()

    try:
        await asyncio.gather(
            client_to_server(),
            forward_raw(upstream_reader, client_writer))
    finally:
        client_writer.close()
        upstream_writer.close()


async def serve(args):
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, args.upstream_host, args.upstream_port,
                                   args.action, args.index, args.capture_client),
        "127.0.0.1", args.listen_port)
    async with server:
        # Explicit parent/child readiness signal; no guessed startup sleep.
        print("TLSLAB_RECORD_PROXY_READY", flush=True)
        await server.serve_forever()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-port", type=int, default=9443)
    ap.add_argument("--upstream-host", default="127.0.0.1")
    ap.add_argument("--upstream-port", type=int, default=8443)
    ap.add_argument("--action", choices=["duplicate", "bitflip", "drop", "truncate", "passthrough"], required=True)
    ap.add_argument("--capture-client", type=Path, default=None)
    ap.add_argument("--index", type=int, required=True)
    args = ap.parse_args()
    if args.capture_client is not None and not args.capture_client.parent.is_dir():
        ap.error("--capture-client parent directory must exist")
    if args.index <= 0:
        ap.error("--index must be positive (1-based)")
    asyncio.run(serve(args))


if __name__ == "__main__":
    main()
