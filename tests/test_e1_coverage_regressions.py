"""Regression checks for E1 coverage and failure provenance fixes.

These tests use mocks; they do not claim that real nginx/BCJSSE runs passed.
"""
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from tlslab import probe_suite, run_e1


def _suite_output(cipher: str, *, exit_code: int = 0, protocol: str = "TLSv1.3"):
    return {
        "status": "OBSERVED",
        "returncode": exit_code,
        "stdout": f"Protocol version: {protocol}\nCiphersuite: {cipher}\n",
        "stderr": "",
        "argv": ["openssl", "s_client"],
    }


def test_pr06_bcjsse_now_observes_negotiated_suite(monkeypatch, tmp_path):
    profile = {
        "provider": "BCJSSE", "bindHost": "127.0.0.1", "httpsPort": 8443,
        "cipherSuites": ["TLS_AES_256_GCM_SHA384",
                         "TLS_CHACHA20_POLY1305_SHA256",
                         "TLS_AES_128_GCM_SHA256"],
    }
    calls = []
    def fake_run(argv, **kwargs):
        calls.append(argv)
        return _suite_output("TLS_AES_256_GCM_SHA384")
    monkeypatch.setattr(probe_suite, "run_tool", fake_run)
    passed = probe_suite.run_probe({"runner": "suite_order"}, profile,
                                   ca_file=tmp_path / "ca.crt")
    assert passed["status"] == "PASS"
    assert calls and "-ciphersuites" in calls[0]
    assert "negotiated=TLS_AES_256_GCM_SHA384" in passed["observed"]

    monkeypatch.setattr(
        probe_suite, "run_tool",
        lambda *args, **kw: _suite_output("TLS_CHACHA20_POLY1305_SHA256"))
    deviated = probe_suite.run_probe({"runner": "suite_order"}, profile,
                                     ca_file=tmp_path / "ca.crt")
    assert deviated["status"] == "FAIL"
    assert "configured_first=TLS_AES_256_GCM_SHA384" in deviated["observed"]


@pytest.mark.parametrize("exit_code,protocol", [(1, "TLSv1.3"), (0, "TLSv1.2")])
def test_pr06_does_not_score_failed_or_wrong_version_handshake(
    monkeypatch, tmp_path, exit_code, protocol
):
    monkeypatch.setattr(
        probe_suite, "run_tool",
        lambda *args, **kwargs: _suite_output(
            "TLS_AES_256_GCM_SHA384", exit_code=exit_code, protocol=protocol))
    profile = {"provider": "BCJSSE", "bindHost": "127.0.0.1",
               "httpsPort": 8443, "cipherSuites": ["TLS_AES_256_GCM_SHA384"]}
    outcome = probe_suite.run_probe({"runner": "suite_order"}, profile,
                                    ca_file=tmp_path / "ca.crt")
    assert outcome["status"] == "INCONCLUSIVE"


def test_b3_nginx_preflight_reports_configuration_error(monkeypatch, tmp_path):
    class FreeSocket:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return None
        def settimeout(self, *_):
            return None
        def connect_ex(self, *_):
            return 111

    monkeypatch.setattr(run_e1.shutil, "which", lambda name: "/usr/bin/nginx")
    monkeypatch.setattr(run_e1.socket, "socket", lambda *a, **k: FreeSocket())
    calls = []
    def fake_subprocess(argv, **kwargs):
        calls.append(argv)
        if "prepare" in argv:
            return SimpleNamespace(returncode=0, stdout="/tmp/nginx-b3.conf\n",
                                   stderr="")
        if "-t" in argv:
            return SimpleNamespace(returncode=1, stdout="",
                                   stderr="nginx: invalid config directive")
        raise AssertionError("nginx should not start after a failed -t")

    monkeypatch.setattr(run_e1.subprocess, "run", fake_subprocess)
    with pytest.raises(RuntimeError, match="invalid config directive"):
        with run_e1.nginx_b3(tmp_path / "B3.log"):
            pass
    assert any("-t" in argv for argv in calls)


def test_e1_does_not_duplicate_rows_after_mid_configuration_exception(
    monkeypatch, tmp_path
):
    (tmp_path / "configs/server").mkdir(parents=True)
    (tmp_path / "pki/out").mkdir(parents=True)
    (tmp_path / "pki/out/ca.crt").write_text("mock CA")
    (tmp_path / "configs/server/P1.yaml").write_text(
        yaml.safe_dump({"provider": "SunJSSE", "httpsPort": 8443,
                        "httpPort": 8080, "cipherSuites": []}))
    run = tmp_path / "data/raw/E1/example"
    run.mkdir(parents=True)
    monkeypatch.setattr(run_e1, "ROOT", tmp_path)
    monkeypatch.setattr(run_e1.os, "getenv",
                        lambda key, default=None: "test-password" if key == "KS_PASS" else default)
    monkeypatch.setattr(run_e1, "verify_base_keystore", lambda path: None)
    monkeypatch.setattr(run_e1, "new_run", lambda *a, **kw: run)
    monkeypatch.setattr(run_e1, "plan",
                        lambda *a: [{"configuration": "P1", "repetition": 1}])
    catalog = [{"id": f"PR{i:02}", "runner": "irrelevant", "category": "test"}
               for i in range(1, 4)]
    monkeypatch.setattr(run_e1, "probe_catalogue", lambda: catalog)
    monkeypatch.setattr(run_e1, "fuzz_keystore", lambda path: tmp_path / "fuzz.p12")
    monkeypatch.setattr(run_e1, "local_ocsp", lambda path: nullcontext())
    monkeypatch.setattr(run_e1, "running_server", lambda *a, **k: nullcontext())
    monkeypatch.setattr(run_e1, "run_probe",
                        lambda *a, **k: {"status": "PASS", "observed": "ok"})
    monkeypatch.setattr(run_e1, "security_score", lambda *a, **k: 1)

    def fake_profile(name, changes, folder):
        folder.mkdir(parents=True, exist_ok=True)
        result = folder / f"profile-{name}.yaml"
        result.write_text("provider: SunJSSE\n")
        return result
    monkeypatch.setattr(run_e1, "ephemeral_server_profile", fake_profile)
    observed = []
    def fake_append(path, payload):
        if len(observed) == 1:
            observed.append("failed-write")
            raise RuntimeError("simulated evidence write crash")
        observed.append(payload)
    monkeypatch.setattr(run_e1, "append_jsonl", fake_append)
    rows_saved = []
    monkeypatch.setattr(run_e1, "to_parquet",
                        lambda rows, path: rows_saved.extend(rows))
    recorded = []
    monkeypatch.setattr(run_e1, "complete_manifest",
                        lambda run, status, details: recorded.append((status, details)))
    run_e1.execute(pilot=True)
    assert len(rows_saved) == 3
    assert [x["probe_id"] for x in rows_saved] == ["PR01", "PR02", "PR03"]
    assert [x["outcome"] for x in rows_saved] == ["PASS", "BLOCKED", "BLOCKED"]
    assert recorded[0][0] == "PARTIAL"
    assert recorded[0][1]["cells"] == 3


def test_e1_configuration_filter_preserves_repetitions_and_rejects_bad_names():
    matrix = [{"configuration": c, "repetition": n}
              for c in ("P1", "B3", "P2") for n in (1, 2, 3)]
    subset = run_e1.select_configurations(matrix, "B3,P2")
    assert len(subset) == 6
    assert [(x["configuration"], x["repetition"]) for x in subset] == [
        (c, n) for c in ("B3", "P2") for n in (1, 2, 3)]
    for bad in ("", ",", "B3,B3", "X9", "B3,"):
        with pytest.raises(ValueError):
            run_e1.select_configurations(matrix, bad)


def test_nginx_b3_prepare_uses_writable_temp_dirs(tmp_path, monkeypatch):
    from scripts import nginx_b3
    source_template = (
        Path(__file__).resolve().parents[1] / "conf/nginx-b3.conf.template"
    ).read_text()
    (tmp_path / "conf").mkdir()
    (tmp_path / "conf/nginx-b3.conf.template").write_text(source_template)
    monkeypatch.setattr(nginx_b3, "ROOT", tmp_path)
    monkeypatch.setattr(nginx_b3, "RUNTIME", tmp_path / "data/runtime")
    output = nginx_b3.prepare(payload=False)
    config = output.read_text()
    for folder in nginx_b3.NGINX_TEMP_SUBDIRS:
        temp = tmp_path / "data/runtime/nginx-temp" / folder
        assert temp.is_dir()
        assert str(temp) in config
    assert "@@ROOT@@" not in config
    assert "/var/lib/nginx/" not in config
