"""Independent byte-level ClientHello and RFC 9846 PR22 verdict regressions."""
import pytest

from tlslab import tls13_wire_probe as wire


@pytest.mark.parametrize("compression", [b"\x00", b"\x01\x00", b"\x01"])
def test_generated_hello_contains_exact_compression_vector(compression):
    record = wire.build_client_hello(compression)
    assert wire.compression_from_hello(record) == compression
    assert record[0] == 22 and record[5] == 1
    assert len(record) == 5 + int.from_bytes(record[3:5], "big")


def test_reject_out_of_scope_hosts():
    with pytest.raises(ValueError, match="only local"):
        wire.first_server_message("example.com", 443, b"\x00")


def test_negative_probe_reports_actual_serverhello_as_failure(monkeypatch):
    monkeypatch.setattr(wire, "first_server_message",
                        lambda host, port, compression: {
                            "response": "server_hello",
                            "sent_compression_hex": compression.hex()})
    result = wire.probe()
    assert result["verdict"] == "FAIL"
    assert result["cases"]["deflate_only"]["sent_compression_hex"] == "01"


def test_negative_probe_uses_both_fatal_illegal_parameter_alerts(monkeypatch):
    def answer(host, port, compression):
        if compression == b"\x00":
            return {"response": "server_hello"}
        return {"response": "alert", "alert": "illegal_parameter", "alert_level": 2}
    monkeypatch.setattr(wire, "first_server_message", answer)
    assert wire.probe()["verdict"] == "PASS"


def test_different_alert_or_unusable_baseline_is_inconclusive(monkeypatch):
    def answer(host, port, compression):
        if compression == b"\x00":
            return {"response": "server_hello"}
        return {"response": "alert", "alert": "handshake_failure", "alert_level": 2}
    monkeypatch.setattr(wire, "first_server_message", answer)
    assert wire.probe()["verdict"] == "INCONCLUSIVE"
    monkeypatch.setattr(wire, "first_server_message",
                        lambda host, port, compression: {"response": "closed"})
    assert wire.probe()["verdict"] == "INCONCLUSIVE"


def test_e1_compression_requires_two_consistent_independent_oracles(monkeypatch):
    from tlslab import probe_suite

    profile = {
        "bindHost": "127.0.0.1", "httpsPort": 8443,
        "namedGroups": ["x25519"],
        "cipherSuites": ["TLS_AES_128_GCM_SHA256"],
    }
    def wire_answer(verdict):
        return {
            "verdict": verdict,
            "cases": {"baseline": {"response": "server_hello"}},
        }
    def native_answer(answer):
        return {"baseline": "accepted", "with_deflate": answer}, {}

    monkeypatch.setattr(
        probe_suite, "native_probe",
        lambda kind, c, *args: native_answer("accepted")
    )
    monkeypatch.setattr(
        probe_suite, "independent_compression_probe",
        lambda *a: wire_answer("FAIL")
    )
    assert probe_suite.tls13_compression(profile)["status"] == "FAIL"

    # Contradictory evidence cannot become a PASS or silently overwrite FAIL.
    monkeypatch.setattr(
        probe_suite, "independent_compression_probe",
        lambda *a: wire_answer("PASS")
    )
    assert probe_suite.tls13_compression(profile)["status"] == "INCONCLUSIVE"

    monkeypatch.setattr(
        probe_suite, "native_probe",
        lambda kind, c, *args: native_answer("alert:illegal_parameter")
    )
    assert probe_suite.tls13_compression(profile)["status"] == "PASS"

    monkeypatch.setattr(
        probe_suite, "independent_compression_probe",
        lambda *a: wire_answer("FAIL")
    )
    assert probe_suite.tls13_compression(profile)["status"] == "INCONCLUSIVE"
