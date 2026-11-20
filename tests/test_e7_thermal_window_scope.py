"""E7 thermal validation must cover measured clients, not setup or later probes."""
import pytest

from tlslab import run_e7


def test_timed_batch_opens_and_closes_thermal_window_on_correct_boundaries(monkeypatch):
    events = []

    class Window:
        def __init__(self):
            events.append("gate-and-start")
        def close(self):
            events.append("close")
            return {"ok": True, "throttle_events": 0, "reasons": [],
                    "gate": {"ok": True, "temp_c": 52.0}}

    def fake_batch(n, *, isolated, host, client_affinity=None,
                   client_warmup=0, status_request=True):
        assert n == 3 and client_warmup == 20
        events.append("timed-client-batch")
        return [1.0, 2.0, 3.0]

    monkeypatch.setattr(run_e7, "ThermalWindow", Window)
    monkeypatch.setattr(run_e7, "handshake_batch", fake_batch)
    observations, window = run_e7.thermally_monitored_batch(
        3, isolated=False, host="127.0.0.1", client_warmup=20)

    assert observations == [1.0, 2.0, 3.0]
    assert events == ["gate-and-start", "timed-client-batch", "close"]
    assert window["throttle_events"] == 0


def test_timed_batch_always_closes_even_if_handshakes_raise(monkeypatch):
    events = []
    class Window:
        def __init__(self):
            events.append("start")
        def close(self):
            events.append("close")
            return {"ok": False, "throttle_events": 1,
                    "reasons": ["throttled"], "gate": {"ok": True}}
    def fail(*args, **kwargs):
        events.append("batch")
        raise RuntimeError("bad TLS handshake")
    monkeypatch.setattr(run_e7, "ThermalWindow", Window)
    monkeypatch.setattr(run_e7, "handshake_batch", fail)
    with pytest.raises(RuntimeError, match="bad TLS handshake"):
        run_e7.thermally_monitored_batch(1, isolated=True, host="10.77.1.1")
    assert events == ["start", "batch", "close"]


def test_thermal_aggregation_preserves_throttling_and_pilot_windows():
    good = {"ok": True, "throttle_events": 0, "reasons": [],
            "gate": {"ok": True}}
    bad = {"ok": False, "throttle_events": 18,
           "reasons": ["18 thermal throttle counter increments"],
           "gate": {"ok": True}}
    clean = run_e7.combine_thermal_windows([good, good])
    assert clean["ok"] and clean["throttle_events"] == 0
    failed = run_e7.combine_thermal_windows([good, bad])
    assert not failed["ok"] and failed["throttle_events"] == 18
    assert "window 2" in failed["reasons"][0]
    assert len(failed["gate"]) == 2


def test_missing_counter_evidence_is_not_accidentally_accepted():
    window = {"ok": False, "throttle_events": None,
              "reasons": ["counter unavailable"], "gate": {"ok": False}}
    result = run_e7.combine_thermal_windows([window])
    assert result["ok"] is False
    assert result["throttle_events"] is None


def test_original_and_reference_use_same_thermal_measurement_helper():
    from tlslab import run_e7_reference
    from pathlib import Path
    source = Path(run_e7_reference.__file__).read_text()
    assert "thermally_monitored_batch(" in source
    assert "thermal_windows.append(measurement_window)" in source
    assert "combine_thermal_windows(thermal_windows)" in source
