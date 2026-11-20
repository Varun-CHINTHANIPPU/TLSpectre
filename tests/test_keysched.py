import hashlib
import hmac
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from tlslab.keysched import (
    SUITES, decrypt_record, finished_verify_data, hkdf_expand,
    hkdf_expand_label, hkdf_extract, record_key_iv, verify_finished,
)


def test_rfc5869_test_case_1():
    # RFC 5869 appendix A.1, SHA-256.
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk = hkdf_extract(salt, ikm)
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba63" + "90b6c73bb50f9c3122ec844ad7c2b3e5"
    assert hkdf_expand(prk, info, 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


@pytest.mark.parametrize("suite", list(SUITES))
def test_tls13_record_roundtrip_and_bad_tag(suite):
    digest, _, aead = SUITES[suite]
    secret = bytes(range(hashlib.new(digest).digest_size))
    key, iv = record_key_iv(secret, suite)
    payload = b"test TLS13 record"
    plaintext = payload + b"\x17\x00\x00"
    record_len = len(plaintext) + 16
    header = b"\x17\x03\x03" + record_len.to_bytes(2, "big")
    encrypted = aead(key).encrypt(iv, plaintext, header)
    record = header + encrypted
    assert decrypt_record(record, secret, suite, 0) == (23, payload)
    with pytest.raises(Exception):
        decrypt_record(record[:-1] + bytes([record[-1] ^ 1]), secret, suite, 0)


@pytest.mark.parametrize("hash_name", ["sha256", "sha384"])
def test_finished_and_label(hash_name):
    secret = bytes(range(hashlib.new(hash_name).digest_size))
    mac = finished_verify_data(secret, b"ClientHelloServerHello", hash_name)
    assert len(mac) == len(secret)
    assert verify_finished(secret, b"ClientHelloServerHello", mac, hash_name)
    assert not verify_finished(secret, b"ClientHelloServerHello!", mac, hash_name)
    assert len(hkdf_expand_label(secret, "key", b"", 16, hash_name)) == 16


def test_malformed_record_is_rejected():
    with pytest.raises(ValueError):
        decrypt_record(b"\x17\x03\x03\x00\x10" + b"x" * 16, b"x" * 32,
                       "TLS_AES_128_GCM_SHA256", 0)
