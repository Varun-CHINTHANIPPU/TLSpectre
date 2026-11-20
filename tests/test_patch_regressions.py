"""Regression tests for reproducible TLS lab failures."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import inspect
import os
import subprocess
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import NameOID, ocsp

from tlslab import probe_protocol, probe_suite, tool_wrappers
from tlslab.e6_pki import sign_response
from tlslab.experiment_control import read_phase_marker, running_server
from tlslab.revocation import k1_curl


def test_openssl_probe_does_not_inherit_terminal_stdin(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(tool_wrappers.subprocess, "run", fake_run)
    tool_wrappers.run_tool(["openssl", "version"])
    tool_wrappers.run_tool(["openssl", "s_client"], stdin="GET / HTTP/1.1\r\n\r\n")
    assert calls[0]["stdin"] == subprocess.DEVNULL
    assert calls[0]["input"] is None
    assert calls[1]["stdin"] is None
    assert calls[1]["input"].endswith("\r\n\r\n")


def test_hsts_ablation_does_not_earn_security_point():
    assert probe_suite.security_score("hsts200", {"hsts": False}, "PASS") == 0
    assert probe_suite.security_score("hsts404", {"hsts": True}, "PASS") == 1
    assert probe_suite.security_score("redirect", {"httpRedirect": False}, "PASS") == 0
    assert probe_suite.security_score("sni_mismatch", {"sniHostCheck": False}, "PASS") == 0
    assert probe_suite.security_score("hsts200", {"hsts": False}, "BLOCKED") is None


def test_legacy_hello_is_scored_against_requested_version(monkeypatch):
    tested = {}

    def fake_from_command(cmd, checker, **kwargs):
        tested["cmd"] = cmd
        verdict, reason = checker({
            "stdout": "", "stderr": "tlsv1 alert protocol version",
            "returncode": 1,
        })
        return {"status": verdict, "observed": reason}

    monkeypatch.setattr(probe_suite, "from_command", fake_from_command)
    profile = {
        "bindHost": "127.0.0.1",
        "httpsPort": 8443,
        "protocols": ["TLSv1.2", "TLSv1.3"],
    }
    assert probe_suite.tls12_trial(profile, Path("ca.crt"), requested="-tls1")["status"] == "PASS"
    assert "DEFAULT:@SECLEVEL=0" in tested["cmd"]


def test_zero_rtt_probe_sends_complete_http_and_checks_ticket(monkeypatch):
    commands = []

    def fake_run_tool(argv, **kwargs):
        commands.append((argv, kwargs))
        if "-sess_out" in argv:
            Path(argv[argv.index("-sess_out") + 1]).write_text("ticket")
            assert kwargs["stdin"].endswith("\r\n\r\n")
        if "sess_id" in argv:
            return {"status": "OBSERVED", "stdout": "Max Early Data: 0", "stderr": "", "returncode": 0}
        return {"status": "OBSERVED", "stdout": "", "stderr": "Early data was not sent", "returncode": 0}

    monkeypatch.setattr(probe_protocol, "run_tool", fake_run_tool)
    observed = probe_protocol.zero_rtt_probe("127.0.0.1", 8443)
    assert observed["status"] == "PASS"
    assert observed["max_early_data"] == 0
    assert len(commands) == 3


def test_proxy_and_bulk_phase_markers_have_bounded_read():
    def pipe_with_message(message: bytes):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, message)
        os.close(write_fd)
        return os.fdopen(read_fd, "rb", buffering=0)

    stream = pipe_with_message(b"TLSLAB_RECORD_PROXY_READY\n")
    try:
        proc = SimpleNamespace(stdout=stream, poll=lambda: None)
        probe_protocol.await_proxy_ready(proc, timeout=1)
    finally:
        stream.close()

    stream = pipe_with_message(b"TLSLAB_E4_WARMUP_COMPLETE\n")
    try:
        assert read_phase_marker(stream, timeout=1) == "TLSLAB_E4_WARMUP_COMPLETE"
    finally:
        stream.close()


def test_server_affinity_applied_before_spawn():
    source = inspect.getsource(running_server)
    assert source.index("argv = pinned(argv, server_affinity)") < source.index("subprocess.Popen(argv")
    assert "os.sched_setaffinity(process.pid" not in source


def test_e7_quantile_and_cold_block_sample_count():
    from tlslab import run_e7
    import numpy as np

    source = inspect.getsource(run_e7.execute)
    assert 'float(np.percentile(timings, 95))' in source
    assert 'count = (2 if pilot else 1) if phase == "cold" else 1' in source
    vals = [345.0, 372.8]
    assert np.percentile(vals, 95) >= np.median(vals)


def test_curl_transport_refusal_is_blocked(monkeypatch):
    monkeypatch.setattr("tlslab.revocation.shutil.which", lambda _: "/usr/bin/curl")
    monkeypatch.setattr("tlslab.revocation.subprocess.run", lambda *a, **k:
                        SimpleNamespace(returncode=7, stdout="000",
                                        stderr="Failed to connect"))
    assert k1_curl("127.0.0.1", 8443, Path("ca.crt"))["outcome"] == "BLOCKED"


def test_ocsp_certid_digest_matches_request_and_freshness():
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test issuer")])
    ca = (x509.CertificateBuilder().subject_name(issuer_name)
          .issuer_name(issuer_name).public_key(key.public_key())
          .serial_number(101).not_valid_before(now - timedelta(days=1))
          .not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab.test")]))
            .issuer_name(issuer_name).public_key(leaf_key.public_key())
            .serial_number(202).not_valid_before(now - timedelta(hours=1))
            .not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    for digest in (hashes.SHA1(), hashes.SHA256()):
        encoded = sign_response(leaf, ca, ca, key, revoked=False,
                                freshness="fresh", algorithm=digest,
                                now=now + timedelta(hours=2))
        response = ocsp.load_der_ocsp_response(encoded)
        assert response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert response.hash_algorithm.name == digest.name
        assert response.certificate_status == ocsp.OCSPCertStatus.GOOD
        assert response.next_update_utc > now + timedelta(hours=2)


def test_pr07_does_not_mistake_cipher_none_for_valid_tls(monkeypatch):
    checked = []
    def fake_from_command(cmd, checker, **kwargs):
        checked.append(cmd)
        def classify(stdout, stderr, rc):
            verdict, _ = checker({"stdout":stdout,"stderr":stderr,"returncode":rc})
            return verdict
        assert classify(
            "", "SSL handshake has read 7 bytes\nCipher is (NONE)\nssl3_read_bytes:tlsv1 alert handshake failure",
            1) == "PASS"
        assert classify(
            "", "Protocol version: TLSv1.3\nCiphersuite: TLS_AES_128_GCM_SHA256",
            0) == "FAIL"
        assert classify("", "Cipher is (NONE)", 1) == "INCONCLUSIVE"
        return {"status":"PASS", "observed":"mock"}
    monkeypatch.setattr(probe_suite, "from_command", fake_from_command)
    profile = {"bindHost":"127.0.0.1","httpsPort":8443}
    assert probe_suite.run_probe(
        {"runner":"group_rejection"}, profile, ca_file=Path("ca.crt")
    )["status"] == "PASS"
    assert "-brief" in checked[0]


def test_testssl_forces_host_openssl(monkeypatch):
    from tlslab import external_probes
    from pathlib import Path
    calls = []
    monkeypatch.setattr(external_probes, "local_tool",
                        lambda name: Path("/tmp/testssl.sh") if name == "testssl.sh" else None)
    monkeypatch.setattr("shutil.which",
                        lambda name: "/usr/bin/openssl" if name == "openssl" else None)
    def fake_run_tool(argv, **kwargs):
        calls.append(argv)
        return {"status":"OBSERVED", "stdout":"protocol scan " * 30,
                "stderr":"", "returncode":0}
    monkeypatch.setattr(external_probes, "run_tool", fake_run_tool)
    outcome=external_probes.run_testssl("127.0.0.1", 8443)
    assert outcome["status"] == "OBSERVED"
    assert calls[0][calls[0].index("--openssl") + 1] == "/usr/bin/openssl"
    assert calls[0][-1] == "127.0.0.1:8443"


def test_capture_output_opened_before_tshark_privilege_drop(monkeypatch, tmp_path):
    from tlslab import capture
    import stat
    calls = []
    class FakePopen:
        def __init__(self, argv, **kwargs):
            calls.append((argv, kwargs))
            self.returncode = None
        def poll(self):
            return self.returncode
        def send_signal(self, _signal):
            self.returncode = 0
        def wait(self, timeout=None):
            return self.returncode
        def kill(self):
            self.returncode = 9
    monkeypatch.setattr(capture.shutil, "which", lambda _: "/usr/bin/tshark")
    monkeypatch.setattr(capture.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(capture.time, "sleep", lambda _sec: None)
    path = tmp_path / "private" / "capture.pcapng"
    with capture.capture_loopback(path):
        pass
    argv, options = calls[0]
    assert argv[-2:] == ["-w", "-"]
    assert options["stdout"].name == str(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_tlsfuzzer_failed_sanity_never_counts_as_security_fail(monkeypatch):
    from tlslab import external_probes
    monkeypatch.setattr(external_probes, "tlsfuzzer_script", lambda _: Path("/fake.py"))
    monkeypatch.setattr(external_probes, "run_tool", lambda *a, **k: {
        "status": "OBSERVED", "returncode": 1, "stderr": "",
        "stdout": ("TOTAL: 4\nPASS: 0\nFAIL: 4\nXPASS: 0\n"
                   "FAILED:\n   'invalid compression methods'\n   'sanity'\n")
    })
    observed = external_probes.run_tlsfuzzer("tlsfuzzer_keyupdate", "127.0.0.1", 8443)
    assert observed["status"] == "INCONCLUSIVE"
    assert observed["counts"]["FAIL"] == 4


def test_tls13_only_compression_uses_native_probe_not_tls12_script(monkeypatch):
    called = []
    monkeypatch.setattr(probe_suite, "run_tlsfuzzer",
                        lambda *a, **k: called.append(a) or {"status": "PASS", "reason": "x"})
    monkeypatch.setattr(probe_suite, "native_probe", lambda kind, c, *extra: (
        {"baseline": "accepted", "with_deflate": "alert:illegal_parameter"}, {}))
    monkeypatch.setattr(probe_suite, "independent_compression_probe", lambda *a, **k: (
        {"verdict": "PASS", "cases": {"baseline": {"response": "server_hello"}}}))
    observed = probe_suite.run_probe(
        {"runner": "tlsfuzzer_compression"},
        {"protocols": ["TLSv1.3"], "bindHost": "127.0.0.1", "httpsPort": 8443},
        ca_file=Path("ca.crt"))
    assert observed["status"] == "PASS"
    assert not called  # the TLS 1.2 upstream script is never run against TLS 1.3-only
