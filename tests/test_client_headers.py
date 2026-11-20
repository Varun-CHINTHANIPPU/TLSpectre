from pathlib import Path

from tlslab.launch import ROOT


def test_handshake_client_columns_match_e5_and_e7_runners():
    src = (ROOT/"java/src/main/java/lab/tls13/client/HandshakeClient.java").read_text()
    fields = ("handshake_ns", "requested_group", "negotiated_group", "resumption")
    for name in fields:
        assert name in src
    for runner in ("run_e5.py","run_e7.py"):
        text=(ROOT/"harness/tlslab"/runner).read_text()
        assert '"hs_ns"' not in text
        assert '"resumed"' not in text


def test_e4_phase_signal_matches_expected_client_output():
    java=(ROOT/"java/src/main/java/lab/tls13/client/BulkClient.java").read_text()
    python=(ROOT/"harness/tlslab/experiment_control.py").read_text()
    assert "TLSLAB_E4_WARMUP_COMPLETE" in java and "TLSLAB_E4_WARMUP_COMPLETE" in python


def test_bulk_phase_barrier_is_opt_in_and_bidirectional():
    java=(ROOT/"java/src/main/java/lab/tls13/client/BulkClient.java").read_text()
    python=(ROOT/"harness/tlslab/experiment_control.py").read_text()
    assert 'System.getenv("TLSLAB_E4_PHASE_MARKER")' in java
    assert "System.in.read() != 'R'" in java
    assert 'process.stdin.write("R")' in python
