"""Specialized PR04, PR09-PR13 active local TLS probes with raw evidence.

For PR09-PR12 transport-fault observation is INCONCLUSIVE without independent
server application logs, because a dropped record or TLS alert alone does not
prove the application's side-effect isolation.
"""
from __future__ import annotations
from pathlib import Path
import os
import re
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

from .tool_wrappers import check_target, run_tool
from .launch import ROOT


def await_proxy_ready(process: subprocess.Popen, timeout: float = 8) -> None:
    """Wait for the proxy's actual listener-ready marker, not a fixed sleep."""
    deadline = time.monotonic() + timeout
    marker = bytearray()
    while time.monotonic() < deadline and len(marker) < 128:
        if process.poll() is not None:
            raise RuntimeError("record proxy exited during startup")
        ready, _, _ = select.select([process.stdout.fileno()], [], [], min(.5, max(0, deadline-time.monotonic())))
        if not ready:
            continue
        char = os.read(process.stdout.fileno(), 1)
        if not char:
            raise RuntimeError("record proxy closed readiness pipe")
        if char == bytes((10,)):
            if marker.decode("ascii", errors="replace") != "TLSLAB_RECORD_PROXY_READY":
                raise RuntimeError("unexpected record proxy readiness marker")
            return
        marker.extend(char)
    raise TimeoutError("record proxy did not signal listener readiness")


def parse_openssl_server_hello(log: str) -> bytes:
    """Decode ServerHello.random from openssl s_client -msg hex dump."""
    lines=log.splitlines()
    start=None
    for i,line in enumerate(lines):
        if "ServerHello" in line and "Handshake" in line and "<<<" in line:
            start=i+1
            break
    if start is None:
        raise ValueError("ServerHello handshake frame not printed")
    words=[]
    for line in lines[start:]:
        if line.startswith("<<<") or line.startswith(">>>"):
            break
        match=re.match(r"^\s+(?:[0-9a-fA-F]{2}\s+){1,48}[0-9a-fA-F]{2}\s*$",line)
        if match:
            words.extend(re.findall(r"\b[0-9a-fA-F]{2}\b",line))
        elif words:
            break
    payload=bytes.fromhex("".join(words))
    if len(payload)<4+2+32 or payload[0]!=2:
        raise ValueError("ServerHello fragment missing or malformed")
    advertised=int.from_bytes(payload[1:4],"big")
    if len(payload)<4+advertised:
        raise ValueError("ServerHello incomplete in -msg trace")
    return payload[6:38]


def sslv3_client_hello_probe(host: str, port: int):
    """Offer SSL 3.0 with a hand-built ClientHello.

    Modern OpenSSL builds cannot emit SSLv3 at all (no -ssl3), which would
    leave PR02 permanently unverifiable. The hello is 3.0 in both the record
    and the handshake, with classic RSA suites and no extensions.
    """
    check_target(host)
    body=(b"\x03\x00"+os.urandom(32)+b"\x00"
          +b"\x00\x08"+b"\x00\x2f\x00\x35\x00\x0a\x00\x05"+b"\x01\x00")
    handshake=b"\x01"+len(body).to_bytes(3,"big")+body
    record=b"\x16\x03\x00"+len(handshake).to_bytes(2,"big")+handshake
    try:
        with socket.create_connection((host,port),timeout=5) as raw:
            raw.settimeout(5)
            raw.sendall(record)
            reply=b""
            try:
                while len(reply)<7:
                    chunk=raw.recv(4096)
                    if not chunk:
                        break
                    reply+=chunk
            except (TimeoutError,socket.timeout):
                return {"status":"INCONCLUSIVE","reason":"no answer to SSLv3 ClientHello before timeout",
                        "reply":reply.hex()}
    except OSError as exc:
        return {"status":"INCONCLUSIVE","reason":"transport error: "+type(exc).__name__}
    evidence={"reply":reply[:16].hex()}
    if len(reply)>=6 and reply[0]==22 and reply[5]==2:
        return {"status":"FAIL","reason":"Server answered an SSLv3 ClientHello with ServerHello",**evidence}
    if len(reply)>=7 and reply[0]==21:
        return {"status":"PASS","reason":f"SSLv3 ClientHello refused with alert {reply[6]}",
                "alert_description":reply[6],**evidence}
    if not reply:
        return {"status":"PASS","reason":"SSLv3 ClientHello refused: connection closed without ServerHello",**evidence}
    return {"status":"INCONCLUSIVE","reason":"unrecognised answer to SSLv3 ClientHello",**evidence}


def tls12_downgrade_sentinel(host: str, port: int):
    check_target(host)
    argv=["openssl","s_client","-tls1_2","-msg",
          "-connect",f"{host}:{port}","-servername","lab.test"]
    observation=run_tool(argv,timeout=20)
    if observation["status"]=="BLOCKED":
        return {"status":"BLOCKED","reason":observation["reason"],"raw":observation}
    try:
        value=parse_openssl_server_hello(observation["stdout"]+"\n"+observation["stderr"])
    except ValueError as exc:
        return {"status":"INCONCLUSIVE","reason":str(exc),"raw":observation}
    # RFC 8446 §4.1.3: DOWNGRD (44 4f 57 4e 47 52 44) + 0x01.
    tag=bytes.fromhex("444f574e47524401")
    return {"status":"PASS" if value.endswith(tag) else "FAIL",
            "reason":"ServerHello.random downgrade marker",
            "random":value.hex(),"marker_found":value.endswith(tag),
            "raw":observation}


def _proxy(action: str, index: int, host: str, port: int, capture: Path | None = None):
    cmd=[sys.executable,"-m","tlslab.record_proxy",
         "--listen-port","9443","--upstream-host",host,
         "--upstream-port",str(port),"--action",action,"--index",str(index)]
    if capture is not None:
        cmd+=["--capture-client",str(capture)]
    env=os.environ.copy()
    env["PYTHONPATH"]=str(ROOT/"harness")+os.pathsep+env.get("PYTHONPATH","")
    return subprocess.Popen(cmd,cwd=ROOT,env=env,stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)


def _stop(process: subprocess.Popen):
    if process.poll() is None:
        process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()


def _request(nonce: str) -> bytes:
    # Keep-alive on purpose: a server that wrongly accepted a duplicated or
    # out-of-sequence record would go on to serve it on the same connection.
    return (f"HEAD /health?tlslab-probe={nonce} HTTP/1.1\r\n"
            f"Host: lab.test\r\n\r\n").encode()


def served(server_log: Path, nonce: str, settle: float = 0.6) -> int:
    """How many times the server application logged a request carrying nonce."""
    time.sleep(settle)
    return server_log.read_text(errors="replace").count("tlslab-probe="+nonce)


def _client_records(capture: Path) -> list[int]:
    """Outer content types of the client->server TLS records seen by the proxy."""
    data=capture.read_bytes() if capture.is_file() else b""
    kinds=[]
    at=0
    while at+5<=len(data):
        size=int.from_bytes(data[at+3:at+5],"big")
        if at+5+size>len(data):
            break
        kinds.append(data[at])
        at+=5+size
    return kinds


def _two_requests(ca: Path, first: str, second: str, *, capture: Path | None = None):
    """TLS 1.3 through the proxy on :9443; send two request records, then drain.

    Returns handshake record count (if capture given), bytes read and how the
    connection ended. A decrypted fatal alert is authenticated by the server's
    traffic keys, so the proxy cannot have forged it.
    """
    context=ssl.create_default_context(cafile=str(ca))
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
    seen={"handshake_type23":None,"received":b"","end":"open"}
    with socket.create_connection(("127.0.0.1",9443),timeout=5) as raw:
        with context.wrap_socket(raw,server_hostname="lab.test") as tls:
            tls.settimeout(4)
            if capture is not None:
                time.sleep(.4)  # let the proxy flush the client's Finished record
                seen["handshake_type23"]=sum(k==23 for k in _client_records(capture))
            try:
                tls.sendall(_request(first))
                time.sleep(.15)   # two separate TLS records, in order
                tls.sendall(_request(second))
                while True:
                    chunk=tls.recv(4096)
                    if not chunk:
                        seen["end"]="closed"
                        break
                    seen["received"]+=chunk
                    if seen["received"].count(b"HTTP/1.1 ")>=2:
                        seen["end"]="both_answered"
                        break
            except ssl.SSLError as exc:
                seen["end"]="alert"
                seen["alert"]=str(exc)[:200]
            except (TimeoutError,socket.timeout):
                seen["end"]="timeout"
            except OSError as exc:
                seen["end"]="reset"
                seen["alert"]=str(exc)[:200]
    seen["responses"]=seen["received"].count(b"HTTP/1.1 ")
    seen["received"]=seen["received"][:120].hex()
    return seen


def calibrate_record_index(host: str, port: int, ca: Path, server_log: Path):
    """Find the client's first application-data record without guessing.

    A pass-through run counts the outer type-23 records the client emitted
    before any request was written (its encrypted Finished flight); the next
    one carries the first request. The same run is the positive control: both
    requests must be logged exactly once by the server application.
    """
    check_target(host)
    first,second=uuid.uuid4().hex,uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="tlslab-calibrate-") as td:
        capture=Path(td)/"client.tls"
        proxy=_proxy("passthrough",1,host,port,capture)
        try:
            try:
                await_proxy_ready(proxy)
            except (RuntimeError,TimeoutError) as exc:
                return {"status":"BLOCKED","reason":str(exc)}
            try:
                seen=_two_requests(ca,first,second,capture=capture)
            except (ssl.SSLError,OSError) as exc:
                return {"status":"BLOCKED","reason":"control handshake failed: "+str(exc)[:200]}
        finally:
            _stop(proxy)
        total=sum(k==23 for k in _client_records(capture))
    counts=(served(server_log,first),served(server_log,second,0))
    handshake=seen["handshake_type23"]
    if counts!=(1,1) or handshake is None or handshake<1 or total<handshake+2:
        return {"status":"BLOCKED",
                "reason":"pass-through control did not produce two logged requests in two records",
                "served":counts,"handshake_type23":handshake,"total_type23":total,"client":seen}
    return {"status":"CALIBRATED","index":handshake+1,"handshake_type23":handshake,
            "total_type23":total,"served":counts,"client":seen}


# Expected server application log counts for (mutated request A, following request B).
MUTATION_EXPECTATION={
    "bitflip":(0,0),    # A fails AEAD; connection is dead before B
    "truncate":(0,0),   # A's body is completed with B's bytes and fails AEAD
    "drop":(0,0),       # B arrives under the wrong sequence number and fails AEAD
    "duplicate":(1,0),  # A once; its replayed copy fails AEAD; B never read
}


def record_mutation_probe(host: str, port: int, ca: Path,
                          action: str, index: int, server_log: Path | None = None):
    check_target(host)
    if action not in MUTATION_EXPECTATION or index<=0:
        raise ValueError("invalid mutation profile")
    first,second=uuid.uuid4().hex,uuid.uuid4().hex
    process=_proxy(action,index,host,port)
    try:
        try:
            await_proxy_ready(process)
        except (RuntimeError, TimeoutError) as exc:
            return {"status":"BLOCKED","reason":str(exc)}
        try:
            seen=_two_requests(ca,first,second)
        except (ssl.SSLError,OSError) as exc:
            return {"status":"INCONCLUSIVE",
                    "reason":"handshake through mutation proxy failed; record index is not an application record",
                    "exception":type(exc).__name__,"message":str(exc)[:200]}
    finally:
        _stop(process)
    if server_log is None:
        return {"status":"INCONCLUSIVE",
                "reason":"Mutation attempted; no server application log available to prove side-effect isolation",
                "client":seen}
    counts=(served(server_log,first),served(server_log,second,0))
    expected=MUTATION_EXPECTATION[action]
    evidence={"action":action,"record_index":index,"served":counts,"expected_served":expected,
              "client":seen,"nonces":[first,second]}
    if counts!=expected:
        return {"status":"FAIL",
                "reason":f"server application processed requests {counts} after {action}; expected {expected}",
                **evidence}
    if seen["end"] not in ("alert","closed","reset"):
        return {"status":"INCONCLUSIVE",
                "reason":f"no request leaked, but the connection ended as '{seen['end']}' rather than an alert/close",
                **evidence}
    return {"status":"PASS",
            "reason":f"{action}: server log shows {counts} (expected); connection ended with {seen['end']}"
                     +(": "+seen["alert"] if seen.get("alert") else ""),
            **evidence}


def zero_rtt_probe(host: str, port: int):
    check_target(host)
    with tempfile.TemporaryDirectory(prefix="tlslab-0rtt-") as td:
        ticket = Path(td) / "session.pem"
        early_request = Path(td) / "request.txt"
        http_request = "GET /health HTTP/1.1\r\nHost: lab.test\r\nConnection: close\r\n\r\n"
        early_request.write_text(http_request)
        # TLS 1.3 issues NewSessionTicket *after* Finished: do not shut
        # s_client down before processing the HTTP response and ticket.
        first = run_tool(
            ["openssl", "s_client", "-tls1_3", "-ign_eof", "-quiet",
             "-sess_out", str(ticket), "-connect", f"{host}:{port}",
             "-servername", "lab.test"],
            timeout=20, stdin=http_request)
        if first["status"] == "BLOCKED":
            return {"status":"BLOCKED", "reason":"OpenSSL could not run the ticket-collection handshake",
                    "first":first}
        if not ticket.is_file() or ticket.stat().st_size == 0:
            # Without a NewSessionTicket there is no PSK, hence no early data.
            # Only claim that when the HTTP exchange demonstrably completed,
            # i.e. the client stayed connected long enough to receive a ticket.
            if first.get("returncode") == 0 and "HTTP/1.1 " in first.get("stdout", ""):
                return {"status":"PASS", "max_early_data":0,
                        "reason":"Server issued no TLS 1.3 session ticket; 0-RTT resumption impossible",
                        "first":first}
            return {"status":"BLOCKED", "reason":"No TLS 1.3 resumable ticket was captured",
                    "first":first}
        session = run_tool(["openssl", "sess_id", "-in", str(ticket), "-text", "-noout"],
                           timeout=10)
        if session["status"] == "BLOCKED" or session["returncode"] != 0:
            return {"status":"INCONCLUSIVE", "reason":"Cannot inspect resumption ticket",
                    "first":first, "session":session}
        description = (session["stdout"] + "\n" + session["stderr"]).lower()
        early_limit = re.search(r"max early data:\s*(\d+)", description)
        if not early_limit:
            return {"status":"INCONCLUSIVE", "reason":"Ticket's early-data limit is missing",
                    "session":session}
        replay = run_tool(
            ["openssl", "s_client", "-tls1_3", "-sess_in", str(ticket),
             "-early_data", str(early_request), "-connect", f"{host}:{port}",
             "-servername", "lab.test", "-state", "-ign_eof"],
            timeout=20, stdin=http_request)
        if replay["status"] == "BLOCKED":
            return {"status":"BLOCKED", "reason":"OpenSSL could not execute the early-data probe",
                    "session":session,"replay":replay}
        output = (replay["stdout"] + "\n" + replay["stderr"]).lower()
        if "early data was accepted" in output:
            return {"status":"FAIL", "reason":"Server accepted TLS 1.3 early data",
                    "max_early_data":int(early_limit.group(1)),"replay":replay}
        if int(early_limit.group(1)) == 0:
            return {"status":"PASS", "reason":"Ticket explicitly advertises max_early_data=0",
                    "max_early_data":0,"replay":replay}
        return {"status":"INCONCLUSIVE",
                "reason":"Nonzero early-data limit without proof of acceptance/rejection",
                "max_early_data":int(early_limit.group(1)),"replay":replay}


def replay_handshake_probe(host: str, port: int, ca: Path, server_log: Path | None = None):
    """Replay a captured client TLS flight on an entirely new TCP connection.

    Capture uses the pass-through lab proxy, *not* SSLKEYLOGFILE. The captured
    bytes contain one request with a unique marker. With a server application
    log the verdict is direct: the marker must have been served exactly once
    (the original connection) and never again for the replayed bytes.
    """
    check_target(host)
    nonce=uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="tlslab-replay-") as td:
        captured=Path(td)/"captured-client.tls"
        proxy=_proxy("passthrough",1,host,port,captured)
        try:
            try:
                await_proxy_ready(proxy)
            except (RuntimeError, TimeoutError) as exc:
                return {"status":"BLOCKED","reason":str(exc)}
            context=ssl.create_default_context(cafile=str(ca))
            context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
            try:
                with socket.create_connection(("127.0.0.1",9443),timeout=5) as raw:
                    with context.wrap_socket(raw,server_hostname="lab.test") as secure:
                        secure.settimeout(5)
                        secure.sendall(_request(nonce).replace(
                            b"\r\n\r\n",b"\r\nConnection: close\r\n\r\n"))
                        secure.recv(256)
            except (ssl.SSLError,OSError) as exc:
                return {"status":"BLOCKED","reason":"Could not capture first valid handshake",
                        "exception":type(exc).__name__}
        finally:
            _stop(proxy)
        if not captured.is_file() or captured.stat().st_size < 40:
            return {"status":"BLOCKED","reason":"No TLS client flight captured"}
        replay=captured.read_bytes()
        kinds=_client_records(captured)
        if replay[0]!=22 or kinds.count(23)<2:
            return {"status":"BLOCKED","reason":"Captured client flight lacks ClientHello or the request record"}
        before=served(server_log,nonce) if server_log is not None else None
        if server_log is not None and before!=1:
            return {"status":"BLOCKED","reason":f"original request logged {before} times; capture run is not a valid baseline"}
        outcome={"client_bytes_replayed":len(replay),"client_record_types":kinds,"nonce":nonce}
        try:
            with socket.create_connection((host,port),timeout=6) as raw:
                raw.settimeout(6)
                raw.sendall(replay)
                observed=b""
                try:
                    while chunk:=raw.recv(65536):
                        observed+=chunk
                    outcome["end"]="closed"
                except (TimeoutError,socket.timeout):
                    outcome["end"]="timeout"
            outcome["server_first_bytes"]=observed[:64].hex()
            outcome["server_bytes"]=len(observed)
        except OSError as exc:
            outcome["end"]="reset"
            outcome["exception"]=type(exc).__name__
        if server_log is None:
            return {"status":"INCONCLUSIVE",
                    "reason":"Replayed captured client flight; no server application log available to prove it was not served",
                    **outcome}
        after=served(server_log,nonce)
        outcome["served_before"],outcome["served_after"]=before,after
        if after!=before:
            return {"status":"FAIL","reason":"Server application served the replayed request",**outcome}
        return {"status":"PASS",
                "reason":f"Replayed flight was not served (request logged once, by the original connection); replay connection ended: {outcome['end']}",
                **outcome}
