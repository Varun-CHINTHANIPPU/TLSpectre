"""PR03 regression suite: an exact wire mutation, not 269 unrelated tests."""
import pytest

from tlslab import probe_suite
from tlslab import tls_version_wire_probe as version_wire
from tlslab.tls13_wire_probe import build_client_hello


def test_missing_supported_versions_mutant_is_complete_and_has_legacy_cipher():
    control = build_client_hello(b"\x00", supported_versions=True,
                                 offer_tls12_cipher=True)
    mutant = build_client_hello(b"\x00", supported_versions=False,
                                offer_tls12_cipher=True)
    assert control[:3] == mutant[:3] == b"\x16\x03\x01"
    assert 43 in version_wire.client_hello_extension_types(control)
    assert 43 not in version_wire.client_hello_extension_types(mutant)
    assert set(version_wire.client_hello_extension_types(control)) - {43} == set(
        version_wire.client_hello_extension_types(mutant))
    for record in (control, mutant):
        pos = 9 + 2 + 32
        pos += 1 + record[pos]  # session ID
        size = int.from_bytes(record[pos:pos+2], "big")
        assert b"\xc0\x2b" in record[pos+2:pos+2+size]  # TLS1.2 ECDHE-ECDSA


@pytest.mark.parametrize("where,expected", [
    ("protocol_version", "PASS"),
    ("handshake_failure", "INCONCLUSIVE"),
    ("closed", "INCONCLUSIVE"),
    ("server_hello", "FAIL"),
])
def test_pr03_distinguishes_protocol_alerts_and_server_hello(monkeypatch, where, expected):
    def fake_first(host, port, compression, *, hello):
        versions = version_wire.client_hello_extension_types(hello)
        if 43 in versions:
            return {"response": "server_hello"}
        if where == "server_hello":
            return {"response": "server_hello"}
        if where == "closed":
            return {"response": "closed"}
        return {"response": "alert", "alert": where, "alert_level": 2}
    monkeypatch.setattr(version_wire, "first_server_message", fake_first)
    result = version_wire.probe()
    assert result["verdict"] == expected
    assert 43 not in result["mutant_extension_types"]


def test_pr03_nonfatal_protocol_version_does_not_pass(monkeypatch):
    def fake_first(host, port, compression, *, hello):
        return ({"response": "server_hello"}
                if 43 in version_wire.client_hello_extension_types(hello)
                else {"response": "alert", "alert": "protocol_version",
                      "alert_level": 1})
    monkeypatch.setattr(version_wire, "first_server_message", fake_first)
    assert version_wire.probe()["verdict"] == "INCONCLUSIVE"


def test_pr03_unusable_valid_control_is_not_a_pass(monkeypatch):
    monkeypatch.setattr(version_wire, "first_server_message",
                        lambda *a, **kw: {"response": "closed"})
    assert version_wire.probe()["verdict"] == "INCONCLUSIVE"


def test_pr03_parse_rejects_corrupted_lengths():
    hello = bytearray(build_client_hello(b"\x00", supported_versions=False))
    hello[3] ^= 1
    with pytest.raises(ValueError, match="length"):
        version_wire.client_hello_extension_types(bytes(hello))


@pytest.mark.parametrize("upstream_status,wire_status,expected", [
    ("INCONCLUSIVE", "PASS", "PASS"),
    ("BLOCKED", "PASS", "PASS"),
    ("FAIL", "PASS", "INCONCLUSIVE"),
    ("PASS", "FAIL", "FAIL"),
    ("PASS", "INCONCLUSIVE", "INCONCLUSIVE"),
])
def test_e1_pr03_preserves_upstream_evidence_without_laundering(
    monkeypatch, tmp_path, upstream_status, wire_status, expected
):
    profile = {"provider": "BCJSSE", "protocols": ["TLSv1.3"],
               "bindHost": "127.0.0.1", "httpsPort": 8443}
    monkeypatch.setattr(
        probe_suite, "supported_versions_wire_probe",
        lambda *args: {"verdict": wire_status, "reason": "test wire oracle"})
    monkeypatch.setattr(
        probe_suite, "run_tlsfuzzer",
        lambda *args, **kwargs: {"status": upstream_status, "reason": "stock suite",
                                 "counts": {"TOTAL": 269, "FAIL": 261}})
    r = probe_suite.run_probe({"runner": "tlsfuzzer_supported_versions"}, profile,
                              ca_file=tmp_path/"ca.crt")
    assert r["status"] == expected
    assert r["evidence"]["supplementary_tlsfuzzer"]["status"] == upstream_status
    assert r["evidence"]["targeted_wire"]["verdict"] == wire_status
    assert "NOT claimed to pass" in r["observed"]


def test_e1_pr03_dualstack_keeps_existing_full_suite(monkeypatch, tmp_path):
    profile = {"protocols": ["TLSv1.2", "TLSv1.3"],
               "bindHost": "127.0.0.1", "httpsPort": 8443}
    monkeypatch.setattr(probe_suite, "supported_versions_wire_probe",
                        lambda *a: pytest.fail("not valid on dual-stack"))
    monkeypatch.setattr(probe_suite, "run_tlsfuzzer",
                        lambda *a, **k: {"status": "PASS", "reason": "upstream ok"})
    r = probe_suite.run_probe({"runner": "tlsfuzzer_supported_versions"}, profile,
                              ca_file=tmp_path/"ca.crt")
    assert r["status"] == "PASS"


def test_pr03_real_openssl_tls13_only_reference(tmp_path):
    """The independent oracle must agree with a real TLS 1.3-only reference."""
    import shutil
    import socket
    import subprocess
    import time

    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("OpenSSL not installed")
    cert = tmp_path / "reference.crt"
    key = tmp_path / "reference.key"
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
         "-days", "1", "-keyout", str(key), "-out", str(cert),
         "-subj", "/CN=lab.test"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen(
        [openssl, "s_server", "-quiet", "-tls1_3", "-accept", str(port),
         "-key", str(key), "-cert", str(cert)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            if process.poll() is not None:
                pytest.fail("OpenSSL reference exited before becoming ready")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("OpenSSL reference did not listen")
        result = version_wire.probe(port=port)
        assert result["verdict"] == "PASS", result
        assert result["control"]["response"] == "server_hello"
        assert result["without_supported_versions"]["alert"] == "protocol_version"
        assert result["without_supported_versions"]["alert_level"] == 2
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
