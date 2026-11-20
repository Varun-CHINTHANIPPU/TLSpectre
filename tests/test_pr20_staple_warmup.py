"""Regression tests for B3 PR15 test credential and PR20 OCSP cache warm-up."""
import pytest

from tlslab.external_probes import classify_failure
from tlslab.probe_suite import classify_staple, staple_probe


MISSING = "CONNECTED(00000003)\nOCSP response: no response sent\n"
MISSING_OPENSSL3 = "CONNECTED(00000003)\nOCSP responses: no responses sent\n"
GOOD = ("OCSP response:\n======\n    OCSP Response Status: successful (0x0)\n"
        "    Cert Status: good\n    Next Update: Nov 19 09:49:32 2026 GMT\n")
REVOKED = GOOD.replace("Cert Status: good", "Cert Status: revoked")


def fake(outputs, *, returncode=0):
    calls = iter(outputs)
    return lambda argv: {"status": "OBSERVED", "stdout": next(calls), "stderr": "",
                         "argv": argv, "returncode": returncode}


def test_staple_classifications():
    assert classify_staple(MISSING) == "missing"
    assert classify_staple(MISSING_OPENSSL3) == "missing"
    assert classify_staple(GOOD) == "good"
    assert classify_staple(REVOKED) == "invalid"


def test_first_handshake_missing_followed_by_good_is_recorded():
    out = staple_probe(["x"], runner=fake([MISSING, GOOD]), sleep=lambda _: None)
    assert out["status"] == "PASS"
    assert out["evidence"]["first_attempt_staple"] == "missing"
    assert out["evidence"]["staple_attempt"] == 2
    assert out["evidence"]["signature_verified_by_probe"] is False


def test_never_stapled_fails_without_erasing_cold_observations():
    out = staple_probe(["x"], attempts=3, runner=fake([MISSING] * 3), sleep=lambda _: None)
    assert out["status"] == "FAIL"
    assert len(out["evidence"]["attempts"]) == 3


def test_bad_staple_fails_immediately_without_retries():
    out = staple_probe(["x"], runner=fake([REVOKED, GOOD]), sleep=lambda _: None)
    assert out["status"] == "FAIL"
    assert len(out["evidence"]["attempts"]) == 1


def test_unconfirmed_client_exit_never_passes():
    out = staple_probe(["x"], runner=fake([GOOD], returncode=1), sleep=lambda _: None)
    assert out["status"] == "INCONCLUSIVE"


def test_unavailable_probe_is_blocked():
    out = staple_probe(["x"], runner=lambda _: {"status": "BLOCKED", "reason": "timeout"},
                       sleep=lambda _: None)
    assert out["status"] == "BLOCKED"


def test_b3_fuzz_certificate_requires_both_files(tmp_path):
    from scripts.nginx_b3 import fuzz_cert_lines
    assert fuzz_cert_lines(None) == ""
    with pytest.raises(FileNotFoundError):
        fuzz_cert_lines(tmp_path)
    (tmp_path / "rsa.crt").write_text("cert")
    (tmp_path / "rsa.key").write_text("key")
    lines = fuzz_cert_lines(tmp_path)
    assert f"ssl_certificate {tmp_path / 'rsa.crt'};" in lines
    assert f"ssl_certificate_key {tmp_path / 'rsa.key'};" in lines


@pytest.mark.parametrize("with_rsa", [False, True])
def test_b3_template_uses_secondary_cert_only_in_e1(tmp_path, monkeypatch, with_rsa):
    from scripts import nginx_b3
    (tmp_path / "conf").mkdir()
    (tmp_path / "conf/nginx-b3.conf.template").write_text(
        (nginx_b3.ROOT / "conf/nginx-b3.conf.template").read_text())
    monkeypatch.setattr(nginx_b3, "ROOT", tmp_path)
    monkeypatch.setattr(nginx_b3, "RUNTIME", tmp_path / "data/runtime")
    fuzz_dir = None
    if with_rsa:
        fuzz_dir = tmp_path / "fuzz"
        fuzz_dir.mkdir()
        (fuzz_dir / "rsa.crt").write_text("cert")
        (fuzz_dir / "rsa.key").write_text("key")
    conf = nginx_b3.prepare(payload=False, fuzz_dir=fuzz_dir).read_text()
    assert "@@" not in conf
    assert conf.count("ssl_certificate ") == (2 if with_rsa else 1)
    assert "srv_plain.crt" in conf
    assert (("rsa.crt" in conf) == with_rsa)


def test_openssl_deferred_keyupdate_not_positive_conformance_evidence():
    observed = {"node": "ExpectNewSessionTicket()",
                "error": "Timeout when waiting for peer message"}
    assert classify_failure("app data split, conversation with KeyUpdate msg",
                            observed, protocols=["TLSv1.3"]) == "permitted_deferral"
    assert classify_failure("some other case", observed,
                            protocols=["TLSv1.3"]) == "unexplained"

def test_openssl_plural_absence_retries_until_good():
    """Regression for real B3 -status transcript from 2026-11-19."""
    attempts = [MISSING_OPENSSL3, MISSING_OPENSSL3, GOOD]
    out = staple_probe(["openssl", "s_client", "-status"], runner=fake(attempts),
                       sleep=lambda _: None)
    assert out["status"] == "PASS"
    assert out["evidence"]["staple_attempt"] == 3
    assert out["evidence"]["first_attempt_staple"] == "missing"
    assert [a["staple"] for a in out["evidence"]["attempts"]] == [
        "missing", "missing", "good"
    ]


def test_openssl_plural_absence_exhausts_all_retries():
    out = staple_probe(["openssl", "s_client", "-status"],
                       runner=fake([MISSING_OPENSSL3] * 5), sleep=lambda _: None)
    assert out["status"] == "FAIL"
    assert len(out["evidence"]["attempts"]) == 5
    assert all(a["staple"] == "missing" for a in out["evidence"]["attempts"])


def test_open_ssl_nonempty_bad_staple_does_not_get_retried():
    out = staple_probe(["x"], runner=fake([REVOKED, GOOD]), sleep=lambda _: None)
    assert out["status"] == "FAIL"
    assert out["evidence"]["attempts"][0]["staple"] == "invalid"

