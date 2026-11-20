from pathlib import Path
from tlslab.experiment_control import ephemeral_server_profile
from tlslab.launch import ROOT
import yaml


def test_ephemeral_e4_profile_is_single_suite(tmp_path):
    p = ephemeral_server_profile("A4", {
        "cipherSuites": ["TLS_AES_128_GCM_SHA256"],
        "maxPayloadBytes": 536870912
    }, tmp_path)
    cfg = yaml.safe_load(p.read_text())
    assert cfg["jvmFlags"][0] == "-XX:+UnlockDiagnosticVMOptions"
    assert cfg["cipherSuites"] == ["TLS_AES_128_GCM_SHA256"]
