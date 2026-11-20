import pytest
from tlslab.probe_protocol import parse_openssl_server_hello


def test_server_hello_downgrade_marker():
    random=b"x"*24+b"DOWNGRD"+b"\x01"
    body=b"\x03\x03"+random+b"\x00\x13\x01\x00"
    hs=b"\x02"+len(body).to_bytes(3,"big")+body
    dump=" ".join(f"{b:02x}" for b in hs)
    trace="<<< TLS 1.2, Handshake [length 0040], ServerHello\n    "+dump+"\n>>> TLS 1.2, Alert\n"
    assert parse_openssl_server_hello(trace)==random


def test_malformed_server_hello_rejected():
    with pytest.raises(ValueError):
        parse_openssl_server_hello("<<< TLS 1.2, Handshake, Certificate\n")
