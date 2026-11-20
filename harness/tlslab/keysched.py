"""TLS 1.3 RFC 8446 HKDF, AEAD record and Finished helpers (not a pcap validator)."""
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

SUITES = {
    "TLS_AES_128_GCM_SHA256": ("sha256", 16, AESGCM),
    "TLS_AES_256_GCM_SHA384": ("sha384", 32, AESGCM),
    "TLS_CHACHA20_POLY1305_SHA256": ("sha256", 32, ChaCha20Poly1305),
}


def hkdf_extract(salt: bytes, ikm: bytes, hash_name: str = "sha256") -> bytes:
    return hmac.new(salt, ikm, hash_name).digest()


def hkdf_expand(secret: bytes, info: bytes, size: int, hash_name: str = "sha256") -> bytes:
    digest_len = hashlib.new(hash_name).digest_size
    if size < 0 or size > 255 * digest_len:
        raise ValueError("HKDF length out of range")
    result, last = bytearray(), b""
    for counter in range(1, (size + digest_len - 1) // digest_len + 1):
        last = hmac.new(secret, last + info + bytes([counter]), hash_name).digest()
        result.extend(last)
    return bytes(result[:size])


def hkdf_expand_label(secret: bytes, label: str, context: bytes,
                      size: int, hash_name: str = "sha256") -> bytes:
    full_label = b"tls13 " + label.encode("ascii")
    if len(full_label) > 255 or len(context) > 255 or not 0 <= size <= 65535:
        raise ValueError("invalid HkdfLabel")
    info = (size.to_bytes(2, "big") + bytes([len(full_label)]) + full_label
            + bytes([len(context)]) + context)
    return hkdf_expand(secret, info, size, hash_name)


def derive_secret(secret: bytes, label: str, transcript: bytes, hash_name: str) -> bytes:
    digest = hashlib.new(hash_name, transcript).digest()
    return hkdf_expand_label(secret, label, digest, len(digest), hash_name)


def finished_verify_data(handshake_traffic_secret: bytes, transcript: bytes,
                         hash_name: str) -> bytes:
    size = hashlib.new(hash_name).digest_size
    finished_key = hkdf_expand_label(handshake_traffic_secret, "finished", b"", size, hash_name)
    return hmac.new(finished_key, hashlib.new(hash_name, transcript).digest(), hash_name).digest()


def verify_finished(secret: bytes, transcript: bytes, received: bytes, hash_name: str) -> bool:
    return hmac.compare_digest(finished_verify_data(secret, transcript, hash_name), received)


def record_key_iv(traffic_secret: bytes, suite: str) -> tuple[bytes, bytes]:
    hash_name, key_len, _ = SUITES[suite]
    key = hkdf_expand_label(traffic_secret, "key", b"", key_len, hash_name)
    iv = hkdf_expand_label(traffic_secret, "iv", b"", 12, hash_name)
    return key, iv


def decrypt_record(record: bytes, traffic_secret: bytes, suite: str, sequence: int) -> tuple[int, bytes]:
    """Return (TLSInnerPlaintext content-type, payload); caller tracks per-direction epoch sequence."""
    if sequence < 0 or sequence >= 1 << 64:
        raise ValueError("sequence out of range")
    if len(record) < 5 or record[0] != 23 or record[1:3] != b"\x03\x03":
        raise ValueError("expected TLS 1.3 outer application_data record")
    declared = int.from_bytes(record[3:5], "big")
    if declared != len(record) - 5 or declared < 17 or declared > 16640:
        raise ValueError("invalid ciphertext length")
    key, iv = record_key_iv(traffic_secret, suite)
    nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))
    _, _, cipher = SUITES[suite]
    plaintext = cipher(key).decrypt(nonce, record[5:], record[:5])
    index = len(plaintext) - 1
    while index >= 0 and plaintext[index] == 0:
        index -= 1
    if index < 0 or plaintext[index] not in (20, 21, 22, 23):
        raise ValueError("invalid TLSInnerPlaintext content type")
    return plaintext[index], plaintext[:index]
