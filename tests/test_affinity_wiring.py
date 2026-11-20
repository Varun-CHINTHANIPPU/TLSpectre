import pytest

from tlslab.env import experiment_affinity
from tlslab.launch import ROOT


def test_timing_runners_use_portable_affinity():
    for name in ("run_e4.py", "run_e5.py", "run_e7.py"):
        src = (ROOT / "harness/tlslab" / name).read_text()
        assert "experiment_affinity()" in src
        assert 'affinity["server"]' in src
        assert 'affinity["client"]' in src
        assert "requires verified P cores" not in src


def test_default_affinity_never_requires_intel_topology(monkeypatch):
    monkeypatch.delenv("TLSLAB_PIN_CPU", raising=False)
    monkeypatch.setattr("tlslab.env.recommended_affinity",
                        lambda: (_ for _ in ()).throw(AssertionError("must not detect P-cores")))
    assert experiment_affinity() == {"server": [], "client": []}


def test_opt_in_affinity_uses_verified_topology(monkeypatch):
    monkeypatch.setenv("TLSLAB_PIN_CPU", "1")
    monkeypatch.setattr("tlslab.env.recommended_affinity",
                        lambda: {"server": [2, 6], "client": [3, 7]})
    assert experiment_affinity() == {"server": [2, 6], "client": [3, 7]}


def test_opt_in_unsupported_hardware_has_actionable_error(monkeypatch):
    monkeypatch.setenv("TLSLAB_PIN_CPU", "1")
    def unavailable():
        raise RuntimeError("No Intel P cores")
    monkeypatch.setattr("tlslab.env.recommended_affinity", unavailable)
    with pytest.raises(RuntimeError, match="unset TLSLAB_PIN_CPU"):
        experiment_affinity()
