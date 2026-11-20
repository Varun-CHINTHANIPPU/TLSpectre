"""Artifact regression checks (synthetic data only)."""
from __future__ import annotations

import json

import pandas as pd

from tlslab.analysis import artifacts


def test_e6_certificate_status_is_not_measurement_status(tmp_path):
    run = tmp_path / "data/raw/E6/synthetic"
    run.mkdir(parents=True)
    (run / "manifest.json").write_text(json.dumps({
        "experiment": "E6", "disposition": "COMPLETE", "metadata": {"pilot": False}
    }))
    pd.DataFrame({
        "status": ["good"] * 300 + ["revoked"] * 300,
        "outcome": ["ACCEPT"] * 300 + ["REJECT"] * 300,
        "validated": [True] * 600,
    }).to_parquet(run / "results.parquet")
    data = artifacts.load_data("E6", root=tmp_path)
    assert len(data) == 600
    assert set(data["status"]) == {"good", "revoked"}


def test_f5_accepts_e5_server_flight_records(monkeypatch, tmp_path):
    data = pd.DataFrame({
        "group": ["x25519", "X25519MLKEM768"],
        "client_hello_bytes": [210, 1500],
        "server_hello_bytes": [120, 1250],
        "encrypted_server_bytes": [850, 1000],
        "client_flight_bytes": [80, 80],
        "server_flight_records": [3, 4],
    })
    monkeypatch.setattr(artifacts, "_measured", lambda experiment, root: data)
    pdf = artifacts.artifact_figure("F5", root=tmp_path)
    assert pdf.exists() and pdf.stat().st_size > 0
