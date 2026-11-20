from pathlib import Path
from tlslab.launch import ROOT


def test_proxy_accepts_pass_through_capture_and_replay_probe_is_wired():
    proxy=(ROOT/"harness/tlslab/record_proxy.py").read_text()
    suite=(ROOT/"harness/tlslab/probe_suite.py").read_text()
    assert '"passthrough"' in proxy
    assert "--capture-client" in proxy
    assert "replay_handshake_probe" in suite
