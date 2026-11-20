from tlslab.probe_suite import probe_catalogue, result
from tlslab.tool_wrappers import check_target
import pytest


def test_catalogue_exact_pr01_through_pr22():
    entries = probe_catalogue()
    assert len(entries) == 22
    assert entries[0]["id"] == "PR01"
    assert entries[-1]["id"] == "PR22"
    assert all(p["runner"] for p in entries)


def test_blocked_is_not_secure_outcome():
    assert result("BLOCKED","missing")["status"] == "BLOCKED"
    with pytest.raises(ValueError):
        result("SECURE","fabricated")


def test_probes_are_local_only():
    check_target("127.0.0.1")
    with pytest.raises(ValueError):
        check_target("example.com")
