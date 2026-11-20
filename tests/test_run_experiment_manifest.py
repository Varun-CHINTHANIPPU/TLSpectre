"""Runner summaries must not overwrite evidence manifest dispositions."""
import json

import pytest

from tlslab.run_experiment import run_summary


def _run(tmp_path, disposition, scope=None):
    details = {} if scope is None else {"scope": scope}
    (tmp_path / "manifest.json").write_text(
        json.dumps({"disposition": disposition, "details": details})
    )
    return tmp_path


def test_full_verified_e2_reports_complete_with_narrow_scope(tmp_path):
    scope = "traffic secrets -> record/Finished"
    summary = run_summary(_run(tmp_path, "COMPLETE", scope), pilot=False)
    assert summary["classification"] == "COMPLETE"
    assert summary["manifest_disposition"] == "COMPLETE"
    assert summary["verification_scope"] == scope


def test_other_experiments_do_not_become_complete_without_evidence(tmp_path):
    summary = run_summary(_run(tmp_path, "PARTIAL"), pilot=False)
    assert summary["classification"] == "PARTIAL"
    assert summary["manifest_disposition"] == "PARTIAL"
    assert "verification_scope" not in summary


def test_pilot_label_does_not_replace_manifest_disposition(tmp_path):
    summary = run_summary(_run(tmp_path, "COMPLETE"), pilot=True)
    assert summary["classification"] == "PILOT"
    assert summary["manifest_disposition"] == "COMPLETE"


def test_incomplete_manifest_cannot_be_reported_as_complete(tmp_path):
    with pytest.raises(ValueError, match="finalize"):
        run_summary(_run(tmp_path, "INCOMPLETE"), pilot=False)
