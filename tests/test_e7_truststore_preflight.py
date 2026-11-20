"""E7 PKCS12 credential preflight must protect pilot/full evidence from bad KS_PASS."""
import os
import subprocess
from pathlib import Path

import pytest

from tlslab import run_e7, run_e7_reference


@pytest.mark.parametrize("returncode", [0, 1])
def test_keytool_preflight_uses_environment_not_password_on_argv(
        monkeypatch, tmp_path, returncode):
    store = tmp_path/"pki/out/truststore.p12"
    store.parent.mkdir(parents=True)
    store.write_bytes(b"test-only-store")
    monkeypatch.setattr(run_e7, "ROOT", tmp_path)
    monkeypatch.setenv("KS_PASS", "secret-just-for-test")
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, returncode, "", "wrong password")

    monkeypatch.setattr(run_e7.subprocess, "run", fake_run)
    if returncode:
        with pytest.raises(ValueError, match="KS_PASS cannot open"):
            run_e7.require_lab_truststore_password()
    else:
        run_e7.require_lab_truststore_password()
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:3] == ["keytool", "-list", "-storetype"]
    assert command[-2:] == ["-storepass:env", "KS_PASS"]
    assert "secret-just-for-test" not in str(command)
    assert kwargs["stdout"] == subprocess.DEVNULL
    assert kwargs["stderr"] == subprocess.PIPE
    assert store.read_bytes() == b"test-only-store"


def test_preflight_rejects_missing_env_before_touching_store(monkeypatch, tmp_path):
    monkeypatch.setattr(run_e7, "ROOT", tmp_path)
    monkeypatch.delenv("KS_PASS", raising=False)
    with pytest.raises(EnvironmentError, match="KS_PASS required"):
        run_e7.require_lab_truststore_password()


def test_preflight_rejects_missing_store(monkeypatch, tmp_path):
    monkeypatch.setattr(run_e7, "ROOT", tmp_path)
    monkeypatch.setenv("KS_PASS", "test-only")
    with pytest.raises(FileNotFoundError, match="truststore.p12"):
        run_e7.require_lab_truststore_password()


def test_both_full_e7_runners_preflight_before_new_evidence():
    for module in (run_e7, run_e7_reference):
        code = Path(module.__file__).read_text()
        execute = code[code.index("def execute(*, pilot: bool, isolated: bool, allow_host_tuning: bool):"):]
        assert execute.index("    require_lab_truststore_password()") < execute.index(
            "    rows = plan(")
