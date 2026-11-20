from pathlib import Path
from tlslab.launch import ROOT


def test_e1_na_does_not_misclassify_as_insecure():
    runner=(ROOT/"harness/tlslab/run_e1.py").read_text()
    artifacts=(ROOT/"harness/tlslab/analysis/artifacts.py").read_text()
    assert '"validated":status["status"] in ("PASS","FAIL","N/A")' in runner
    assert 'scores["outcome"]=="N/A"' in artifacts
