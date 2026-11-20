"""E7 independent nginx reference: no synthetic evidence or accidental main-matrix reuse."""
import json
from pathlib import Path

import pytest

from tlslab import evidence
from tlslab import run_e7_reference as ref


@pytest.mark.parametrize("stapling", ["off", "warm", "cold"])
@pytest.mark.parametrize("isolated", [False, True])
def test_b3_reference_config_is_isolated_and_controlled(tmp_path, monkeypatch,
                                                        stapling, isolated):
    (tmp_path/"conf").mkdir()
    original = ref.ROOT / "conf/nginx-b3.conf.template"
    (tmp_path/"conf/nginx-b3.conf.template").write_text(original.read_text())
    monkeypatch.setattr(ref, "ROOT", tmp_path)
    folder = tmp_path/"reference"/f"{stapling}-{isolated}"
    cert, key = tmp_path/"cert.pem", tmp_path/"key.pem"
    result = ref.reference_nginx_config(
        folder, cert=cert, key=key, isolated=isolated, stapling=stapling)
    source = result.read_text()
    expected_host = "10.77.1.1" if isolated else "127.0.0.1"
    assert f"listen {expected_host}:8443 ssl;" in source
    assert "ssl_session_tickets off;" in source
    assert f"ssl_certificate {cert};" in source
    assert f"ssl_certificate_key {key};" in source
    assert f"pid {folder/'nginx.pid'};" in source
    assert "nginx-b3-error.log" not in source
    assert "@@" not in source
    assert "ssl_stapling off;" in source if stapling == "off" else "ssl_stapling on;" in source
    assert "ssl_stapling_verify off;" in source if stapling == "off" else "ssl_stapling_verify on;" in source


def test_b3_reference_config_rejects_invalid_mode(tmp_path):
    with pytest.raises(ValueError, match="stapling"):
        ref.reference_nginx_config(tmp_path, cert=tmp_path/"cert", key=tmp_path/"key",
                                   isolated=False, stapling="unknown")


def test_reference_collection_cannot_contaminate_original_e7(tmp_path, monkeypatch):
    monkeypatch.setattr(evidence, "ROOT", tmp_path)
    run = evidence.new_run("E7", {"reference_only": True}, collection="references")
    assert run.parent == tmp_path/"data/references/E7"
    assert not (tmp_path/"data/raw/E7").exists()
    manifest = json.loads((run/"manifest.json").read_text())
    assert manifest["metadata"]["reference_only"] is True
    with pytest.raises(ValueError, match="collection"):
        evidence.new_run("E7", collection="../raw")


def test_b3_reference_cold_timing_precedes_status_probe():
    source = (ref.ROOT/"harness/tlslab/run_e7_reference.py").read_text()
    # Cold-mode checks must occur after the timed first handshake, not
    # before it. This is a static regression guard for the source sequence.
    timer = source.index("samples, measurement_window = thermally_monitored_batch(")
    window_end = source.index("thermal_windows.append(measurement_window)", timer)
    cold = source.index('if mode == "cold":', window_end)
    probe = source.index("history += await_good_staple", cold)
    assert timer < window_end < cold < probe


def test_reference_response_signature_is_not_claimed_verified():
    source = (ref.ROOT/"harness/tlslab/run_e7_reference.py").read_text()
    assert '"signature_verified_by_probe": False' in source
    assert 'collection="references"' in source


@pytest.mark.parametrize("isolated", [True, False])
def test_nginx_reference_config_validation_uses_same_network_namespace(
        tmp_path, monkeypatch, isolated):
    """Regression for 180/180 failures: nginx -t must see netns-only 10.77.1.1."""
    import subprocess
    commands = []

    class Process:
        def __init__(self):
            self.terminated = False
        def poll(self):
            return 0 if self.terminated else None
        def terminate(self):
            self.terminated = True
        def wait(self, timeout=None):
            return 0

    def run(command, **kwargs):
        commands.append(list(command))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def popen(command, **kwargs):
        commands.append(list(command))
        return Process()

    monkeypatch.setattr(ref.shutil, "which", lambda name: "/usr/sbin/nginx")
    monkeypatch.setattr(ref.subprocess, "run", run)
    monkeypatch.setattr(ref.subprocess, "Popen", popen)

    conf = tmp_path / "nginx.conf"
    conf.write_text("test fixture")
    with ref.nginx_reference_server(conf, tmp_path / "nginx.log", isolated=isolated):
        pass

    assert len(commands) == 3  # nginx -t, nginx daemon, TCP readiness
    check, daemon, ready = commands
    prefix = ["ip", "netns", "exec", "tlslab-srv"] if isolated else []
    for command in commands:
        assert command[:len(prefix)] == prefix
    assert check[-1] == "-t"
    assert daemon[-2:] == ["-g", "daemon off;"]
    assert ("10.77.1.1" in " ".join(ready)) == isolated


@pytest.mark.parametrize("isolated", [True, False])
def test_nginx_reference_configuration_error_stops_before_server_start(
        tmp_path, monkeypatch, isolated):
    import subprocess
    calls = []
    monkeypatch.setattr(ref.shutil, "which", lambda name: "/usr/sbin/nginx")

    def fail_config(command, **kwargs):
        calls.append(list(command))
        return subprocess.CompletedProcess(command, 1, stdout="",
                                           stderr="invalid nginx reference")
    monkeypatch.setattr(ref.subprocess, "run", fail_config)
    monkeypatch.setattr(
        ref.subprocess, "Popen",
        lambda *a, **kw: pytest.fail("nginx must not launch after failed -t"))

    with pytest.raises(RuntimeError, match="invalid nginx reference"):
        with ref.nginx_reference_server(
                tmp_path/"nginx.conf", tmp_path/"nginx.log", isolated=isolated):
            pass
    assert len(calls) == 1
    assert calls[0][:4] == (["ip", "netns", "exec", "tlslab-srv"] if isolated
                          else ["/usr/sbin/nginx", "-p", str(ref.ROOT)+"/", "-c"])
