"""Historical scoped E1 reruns cannot contaminate final figures or be pooled."""
import json

import pandas as pd
import pytest

from tlslab.experiment_matrix import plan
from tlslab.analysis.artifacts import _measured, InsufficientEvidence


def write_run(root, name, *, complete, scoped=False):
    out=root/"data/raw/E1"/name
    out.mkdir(parents=True)
    rows = [{**cell,"probe_id":f"PR{n:02d}","category":"test",
             "outcome":"PASS","validated":True,"secure_outcome":1}
            for cell in plan("E1") for n in range(1,23)]
    if scoped:
        rows=rows[:3]
    pd.DataFrame(rows).to_parquet(out/"results.parquet")
    (out/"manifest.json").write_text(json.dumps({
        "experiment":"E1", "disposition":"COMPLETE" if complete else "PARTIAL",
        "metadata":{"pilot":False}}))
    return out


def test_only_fresh_full_complete_e1_is_selected(tmp_path):
    write_run(tmp_path,"old-full",complete=False)
    write_run(tmp_path,"new-scoped",complete=True,scoped=True)
    write_run(tmp_path,"final-full",complete=True)
    result=_measured("E1",tmp_path)
    assert len(result)==528
    assert result["validated"].eq(True).all()


def test_scoped_plus_partial_is_not_sufficient_for_e1_publication(tmp_path):
    write_run(tmp_path,"old-full",complete=False)
    write_run(tmp_path,"new-scoped",complete=True,scoped=True)
    with pytest.raises(InsufficientEvidence, match="no non-pilot|exactly one"):
        _measured("E1",tmp_path)


def test_multiple_full_e1_campaigns_require_explicit_resolution(tmp_path):
    write_run(tmp_path,"first",complete=True)
    write_run(tmp_path,"second",complete=True)
    with pytest.raises(InsufficientEvidence, match="exactly one"):
        _measured("E1",tmp_path)


def test_e1_duplicate_factor_cells_are_not_publication_evidence(tmp_path):
    out=write_run(tmp_path,"final-full",complete=True)
    frame=pd.read_parquet(out/"results.parquet")
    frame.loc[0,["configuration","repetition","probe_id"]] = (
        frame.loc[1,["configuration","repetition","probe_id"]])
    frame.to_parquet(out/"results.parquet")
    with pytest.raises(InsufficientEvidence, match="duplicate"):
        _measured("E1",tmp_path)
