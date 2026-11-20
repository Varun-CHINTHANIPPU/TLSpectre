"""E3 must preserve JMH failures, not silently report a successful pilot."""
import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pandas as pd

from tlslab import run_e3, run_experiment


@contextmanager
def _untuned(_):
    yield {"tuned": False}


def test_e3_all_failed_pilot_records_command_and_jmh_logs(tmp_path, monkeypatch):
    bench = tmp_path/"java"/"bench"/"target"/"benchmarks.jar"
    bench.parent.mkdir(parents=True)
    bench.touch()
    run = tmp_path/"pilot"
    run.mkdir()
    (run/"manifest.json").write_text(json.dumps({
        "experiment": "E3", "disposition": "INCOMPLETE",
        "metadata": {"pilot": True},
    }))
    monkeypatch.setattr(run_e3, "ROOT", tmp_path)
    monkeypatch.setattr(run_e3, "new_run", lambda *args, **kwargs: run)
    monkeypatch.setattr(run_e3, "managed_host_tuning", _untuned)
    monkeypatch.setattr(run_e3, "require_jdk", lambda *a, **k: 27)
    monkeypatch.setattr(run_e3, "performance_snapshot",
                        lambda: {"cpu_controls": {}, "freq_mhz": {}, "thermal_c": {}})
    monkeypatch.setattr(run_e3, "experiment_affinity",
                        lambda: {"server": [], "client": []})
    commands = []

    def fail_jmh(cmd, **kwargs):
        commands.append(cmd)
        return SimpleNamespace(returncode=1, stdout="JMH fork failed: ARCH_TEST",
                               stderr="Unrecognized VM option: ARCH_TEST")

    monkeypatch.setattr(run_e3.subprocess, "run", fail_jmh)
    assert run_e3.execute(pilot=True) == run
    assert len(commands) == 2
    assert (run/"jmh-tmp").is_dir()
    assert all(command[1] == f"-Djava.io.tmpdir={run/'jmh-tmp'}" for command in commands)
    frame = pd.read_parquet(run/"results.parquet")
    assert len(frame) == 2
    assert frame["status"].eq("FAILED").all()
    assert frame["error"].str.contains("ARCH_TEST").all()
    assert not frame["validated"].any()
    assert "fork" not in frame.columns  # avoid assuming failed cells have measurements
    manifest = json.loads((run/"manifest.json").read_text())
    assert manifest["disposition"] == "FAILED"
    assert manifest["details"]["failures"] == 2
    records = [json.loads(x) for x in (run/"evidence.jsonl").read_text().splitlines()]
    assert len(records) == 2
    for index, item in enumerate(records):
        assert item["command"] == commands[index]
        assert item["returncode"] == 1
        assert item["status"] == "FAILED"
        assert "ARCH_TEST" in (run/"logs"/f"{index:04d}.stdout.log").read_text()
        assert "ARCH_TEST" in (run/"logs"/f"{index:04d}.stderr.log").read_text()


def test_e3_cli_exits_nonzero_after_saving_failed_pilot(tmp_path, monkeypatch, capsys):
    import sys
    (tmp_path/"manifest.json").write_text(json.dumps({
        "experiment": "E3", "disposition": "FAILED",
        "metadata": {"pilot": True},
        "details": {"measured_forks": 0, "failures": 2},
    }))
    monkeypatch.setattr(run_e3, "execute", lambda **kwargs: tmp_path)
    monkeypatch.setattr(sys, "argv", ["tlslab.run_experiment", "E3", "--run", "--pilot"])
    assert run_experiment.main() == 2
    captured = capsys.readouterr()
    assert '"manifest_disposition": "FAILED"' in captured.out
    assert "2 JMH cell(s) failed" in captured.err


def test_e3_cli_zero_exit_for_complete_measurement_without_scientific_validation(tmp_path, monkeypatch, capsys):
    import sys
    (tmp_path/"manifest.json").write_text(json.dumps({
        "experiment": "E3", "disposition": "PARTIAL",
        "metadata": {"pilot": True},
        "details": {"measured_forks": 2, "failures": 0},
    }))
    monkeypatch.setattr(run_e3, "execute", lambda **kwargs: tmp_path)
    monkeypatch.setattr(sys, "argv", ["tlslab.run_experiment", "E3", "--run", "--pilot"])
    assert run_experiment.main() == 0
    assert '"manifest_disposition": "PARTIAL"' in capsys.readouterr().out


def test_e3_checker_reports_missing_jmh_metrics_without_crashing(tmp_path, monkeypatch):
    from tlslab import check_fixes

    frame = pd.DataFrame({
        "status": ["FAILED", "FAILED"],
        "validation_failures": ["not measured", "not measured"],
    })
    monkeypatch.setattr(check_fixes, "load", lambda _: (tmp_path, {}, frame))
    check_fixes.RESULTS.clear()
    check_fixes.check_e3(str(tmp_path))
    checks = check_fixes.RESULTS[:]
    check_fixes.RESULTS.clear()
    assert any(status == "FAIL" and "JMH cells measured" in name for status, name, _ in checks)
    assert any(status == "FAIL" and "cpu_ns_per_byte" in name for status, name, _ in checks)
    assert not any("crashed" in name.lower() for _, name, _ in checks)
