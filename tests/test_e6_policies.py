from pathlib import Path
import pytest

from tlslab.experiment_matrix import e6_conditions
from tlslab.revocation import java_policy


def test_java_policy_rejects_unknown():
    with pytest.raises(ValueError):
        java_policy("127.0.0.1", 8443, "K1", Path("x.p12"))


def test_e6_has_24_scenarios_and_five_explicit_policies():
    from yaml import safe_load
    assert len(e6_conditions()) == 24
    cfg = safe_load(Path("configs/experiments/E6.yaml").read_text())
    assert len(cfg["policies"]) == 5
