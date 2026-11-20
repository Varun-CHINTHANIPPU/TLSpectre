from pathlib import Path
import hashlib
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tlslab.keysched import record_key_iv, finished_verify_data
from tlslab.traceverify.trace import (
    TraceError, Record, keylog, parse_tls_records, parse_handshake_messages, verify_records,
)


def record(typ, data):
    return bytes([typ,3,3]) + len(data).to_bytes(2,"big") + data


def encrypt(plain, secret, sequence):
    suite = "TLS_AES_128_GCM_SHA256"
    key, iv = record_key_iv(secret, suite)
    nonce = bytes(x ^ y for x,y in zip(iv, sequence.to_bytes(12,"big")))
    header = bytes([23,3,3]) + (len(plain)+16).to_bytes(2,"big")
    return header + AESGCM(key).encrypt(nonce, plain, header)


def test_packet_reassembly_and_retransmission():
    raw = record(22, b"hello")
    chunks = [(1, 1.0, raw[:3]), (4, 1.1, raw[3:]),
              (1, 1.2, raw)]  # redundant retransmit
    parsed = parse_tls_records(chunks, "client")
    assert len(parsed)==1 and parsed[0].data==raw
    with pytest.raises(TraceError):
        parse_tls_records([(1,1.0,raw[:3]),(6,1.1,raw[3:])], "client")


def test_read_keylog(tmp_path):
    path = tmp_path/"keys.log"
    random = "ab"*32
    path.write_text("CLIENT_HANDSHAKE_TRAFFIC_SECRET " + random + " " + "ab"*32 + "\n")
    assert keylog(path)[random]["CLIENT_HANDSHAKE_TRAFFIC_SECRET"] == b"\xab"*32


def test_live_style_finished_and_tag_verification():
    client_hs, server_hs = bytes(range(32)), bytes(range(32,64))
    client_app, server_app = b"a"*32, b"b"*32
    secrets = dict(
        CLIENT_HANDSHAKE_TRAFFIC_SECRET=client_hs, SERVER_HANDSHAKE_TRAFFIC_SECRET=server_hs,
        CLIENT_TRAFFIC_SECRET_0=client_app, SERVER_TRAFFIC_SECRET_0=server_app)
    def msg(typ, data):
        return bytes([typ]) + len(data).to_bytes(3,"big") + data
    ch = msg(1, b"client")
    sh = msg(2, b"server")
    ee = msg(8, b"")
    cf = msg(20, finished_verify_data(
        client_hs,
        ch + sh + ee + msg(20, finished_verify_data(server_hs, ch+sh+ee,"sha256")),
        "sha256"))
    sf = msg(20, finished_verify_data(server_hs, ch+sh+ee,"sha256"))
    records = [
        Record("client",1,record(22,ch)),
        Record("server",2,record(22,sh)),
        Record("server",3,encrypt(ee + b"\x16",server_hs,0)),
        Record("server",4,encrypt(sf + b"\x16",server_hs,1)),
        Record("client",5,encrypt(cf + b"\x16",client_hs,0)),
        Record("server",6,encrypt(b"HTTP/1.1 200 OK" + b"\x17",server_app,0)),
    ]
    result = verify_records(records,secrets,"TLS_AES_128_GCM_SHA256")
    assert result["finished"] == {"server":1,"client":1}
    assert result["verified_aead_records"]==4
    bad = list(records)
    bad[-1] = Record("server",6,bad[-1].data[:-1] + bytes([bad[-1].data[-1] ^ 1]))
    with pytest.raises(TraceError):
        verify_records(bad,secrets,"TLS_AES_128_GCM_SHA256")
