from tlslab.launch import ROOT


def test_e7_cold_probe_occurs_after_measured_first_handshake():
    source=(ROOT/"harness/tlslab/run_e7.py").read_text()
    start=source.index('                        if phase == "warm"')
    end=source.index('                if phase != "cold"',start)
    section=source[start:end]
    start_batch = section.index("samples, measurement_window = thermally_monitored_batch(")
    end_batch = section.index("thermal_windows.append(measurement_window)", start_batch)
    probe = section.index('if phase == "cold" and not check_staple', end_batch)
    assert start_batch < end_batch < probe


def test_t2_all_12_hardening_controls_are_explicit():
    from tlslab.analysis.artifacts import artifact_table
    import pandas as pd
    path=artifact_table("T2",root=ROOT)
    frame=pd.read_csv(path)
    assert len([x for x in frame.columns if x.startswith("HC")])==12
    path.unlink()
