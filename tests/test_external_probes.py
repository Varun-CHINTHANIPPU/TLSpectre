import pytest
from tlslab.external_probes import SCRIPT_BY_ACTION, run_tlsfuzzer


def test_real_tlsfuzzer_entrypoint_names():
    assert SCRIPT_BY_ACTION["tlsfuzzer_supported_versions"]=="test-tls13-version-negotiation.py"
    assert SCRIPT_BY_ACTION["tlsfuzzer_keyupdate"]=="test-tls13-keyupdate.py"


def test_rejects_non_local_host():
    with pytest.raises(ValueError):
        run_tlsfuzzer("tlsfuzzer_keyupdate","example.com",8443)
