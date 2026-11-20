"""Evidence-based validation for E2-E7: wire parsing, E6 oracle, thermal and row rules."""
import hashlib
import json
import struct
from pathlib import Path

import pytest

from tlslab import env, run_e3, run_e4, run_e5, run_e7
from tlslab.experiment_matrix import e6_conditions
from tlslab.revocation import expected_outcome
from tlslab.wire_capture import (FULL_RECORD, handshake_summary, parse_server_hello,
                                 record_size_summary)


def _ext(kind, data):
    return struct.pack("!HH", kind, len(data)) + data


def _record(kind, payload):
    return bytes((kind, 3, 3)) + struct.pack("!H", len(payload)) + payload


def _hs(kind, body):
    return bytes((kind,)) + len(body).to_bytes(3, "big") + body


def client_hello(groups=(0x11ec,), psk=False):
    shares = b"".join(struct.pack("!HH", g, 4) + b"\0" * 4 for g in groups)
    ext = (_ext(10, struct.pack("!H", 2 * len(groups)) + b"".join(struct.pack("!H", g) for g in groups))
           + _ext(51, struct.pack("!H", len(shares)) + shares)
           + _ext(43, b"\x02\x03\x04") + (_ext(41, b"\0\0") if psk else b""))
    body = b"\x03\x03" + b"\1" * 32 + b"\0" + b"\0\2\x13\1" + b"\1\0" + struct.pack("!H", len(ext)) + ext
    return _hs(1, body)


def server_hello(group=0x11ec, hrr=False, psk=False):
    random = hashlib.sha256(b"HelloRetryRequest").digest() if hrr else b"\2" * 32
    share = struct.pack("!H", group) + (b"" if hrr else struct.pack("!H", 4) + b"\0" * 4)
    ext = _ext(43, b"\x03\x04") + _ext(51, share) + (_ext(41, b"\0\0") if psk else b"")
    body = b"\x03\x03" + random + b"\0" + b"\x13\x01" + b"\0" + struct.pack("!H", len(ext)) + ext
    return _hs(2, body)


def write_conn(tmp_path, c2s, s2c):
    stem = tmp_path / "conn-0001"
    Path(f"{stem}.c2s").write_bytes(c2s)
    Path(f"{stem}.s2c").write_bytes(s2c)
    times = [{"d": "c2s", "o": 0, "t": 0.0}, {"d": "s2c", "o": 0, "t": 1.0},
             {"d": "c2s", "o": len(c2s) - 30, "t": 2.0}]
    Path(f"{stem}.times.jsonl").write_text("\n".join(json.dumps(t) for t in times))
    return stem


def test_handshake_summary_reads_group_hrr_and_psk(tmp_path):
    c2s = _record(22, client_hello()) + _record(20, b"\1") + _record(23, b"F" * 25)
    s2c = _record(22, server_hello()) + _record(20, b"\1") + _record(23, b"E" * 800)
    facts = handshake_summary(write_conn(tmp_path, c2s, s2c))
    assert facts["negotiated_group"] == "X25519MLKEM768"
    assert not facts["hrr"] and not facts["psk_offered"] and not facts["psk_accepted"]
    assert facts["encrypted_server_bytes"] == 805
    assert facts["client_flight_bytes"] == 6 + 30


def test_hrr_and_resumption_are_detected():
    assert parse_server_hello(server_hello(hrr=True)[4:])["hrr"] is True
    assert parse_server_hello(server_hello(psk=True)[4:])["psk_accepted"] is True


def test_record_size_summary(tmp_path):
    stem = tmp_path / "conn-0001"
    Path(f"{stem}.s2c").write_bytes(_record(23, b"x" * FULL_RECORD) * 300 + _record(23, b"y" * 40))
    good = record_size_summary(stem, minimum_body=4 << 20)
    assert good["ok"] and good["max_record_ciphertext"] == FULL_RECORD
    Path(f"{stem}.s2c").write_bytes(_record(23, b"x" * 600) * 9000)
    assert not record_size_summary(stem, minimum_body=4 << 20)["ok"]


def test_e6_oracle_covers_every_scenario_and_known_observations():
    for scenario in e6_conditions():
        for policy in ("K1", "K2", "K3", "K4", "K5"):
            assert expected_outcome(scenario, policy) in ("ACCEPT", "REJECT")
    base = {"must_staple": False, "responder_reachable": False, "stapling": "off", "freshness": "none"}
    # Soft-fail accepts a revoked certificate when nothing can be learned.
    assert expected_outcome({**base, "status": "revoked"}, "K3") == "ACCEPT"
    assert expected_outcome({**base, "status": "revoked"}, "K2") == "REJECT"
    expired = {**base, "status": "good", "stapling": "on", "freshness": "expired",
               "responder_reachable": True}
    assert [expected_outcome(expired, k) for k in ("K1", "K2", "K3", "K4", "K5")] == [
        "REJECT", "REJECT", "REJECT", "ACCEPT", "ACCEPT"]


def test_thermal_window_requires_counters_and_zero_events(monkeypatch):
    monkeypatch.setattr(env, "package_temperature", lambda: 55.0)
    counts = iter([{"cpu0/core_throttle_count": 4}, {"cpu0/core_throttle_count": 4}])
    monkeypatch.setattr(env, "throttle_counters", lambda: next(counts))
    assert env.ThermalWindow().close()["ok"] is True
    counts = iter([{"cpu0/core_throttle_count": 4}, {"cpu0/core_throttle_count": 6}])
    monkeypatch.setattr(env, "throttle_counters", lambda: next(counts))
    window = env.ThermalWindow().close()
    assert not window["ok"] and window["throttle_events"] == 2
    monkeypatch.setattr(env, "throttle_counters", lambda: {})
    assert not env.ThermalWindow().close()["ok"]


def test_thermal_gate_waits_then_gives_up(monkeypatch):
    monkeypatch.setattr(env, "package_temperature", lambda: 95.0)
    monkeypatch.setattr(env.time, "sleep", lambda s: None)
    gate = env.thermal_gate(max_c=70, wait_s=0)
    assert gate["ok"] is False and gate["temp_c"] == 95.0


def test_controls_established():
    assert env.controls_established({"governors": {"cpu0": "performance"}, "intel_no_turbo": "1"})
    assert not env.controls_established({"governors": {"cpu0": "powersave"}, "intel_no_turbo": "1"})
    assert not env.controls_established({"governors": {}, "intel_no_turbo": "1"})


def test_e3_row_validation_lists_every_reason():
    row = {"status": "MEASURED", "cpu_ns_per_byte": 0.2, "thermal_ok": True}
    assert run_e3.validation_failures(row, pilot=False, jdk=27, controls=(True, True)) == []
    reasons = run_e3.validation_failures({**row, "cpu_ns_per_byte": None, "thermal_ok": False},
                                         pilot=False, jdk=21, controls=(True, False))
    assert len(reasons) == 4


def test_e3_cpu_time_parsed_from_jmh_aux_counters():
    jmh = {"primaryMetric": {"rawData": [[100.0, 100.0]], "scoreUnit": "ops/s"},
           "secondaryMetrics": {"cpuNanos": {"rawData": [[5e8, 5e8]]},
                                "bytes": {"rawData": [[2e9, 2e9]]}}}
    row = run_e3.fork_rows(jmh, {"size": 16384})[0]
    assert row["cpu_ns_per_byte"] == pytest.approx(0.25)


def test_e4_e5_e7_rules():
    ok4 = {"status": "MEASURED", "suite_verified": True, "record_size_ok": True, "thermal_ok": True}
    assert run_e4.validation_failures(ok4, pilot=False, pinning_requested=False) == []
    assert run_e4.validation_failures({**ok4, "server_affinity_verified": False},
                                      pilot=False, pinning_requested=True)
    ok5 = {"status": "MEASURED", "group_verified": True, "resumption_verified": True,
           "tls13_verified": True, "hrr_rate": 0.0}
    assert run_e5.validation_failures(ok5, pilot=False, isolated=True) == []
    assert run_e5.validation_failures({**ok5, "hrr_rate": 0.1}, pilot=False, isolated=True)
    ok7 = {"status": "MEASURED", "full_handshake_verified": True, "thermal_ok": True}
    assert run_e7.validation_failures(ok7, pilot=False, isolated=True, jdk=27) == []
    assert run_e7.validation_failures(ok7, pilot=False, isolated=False, jdk=27)


def test_e5_wire_verification_rejects_wrong_group():
    facts = {"negotiated_group": "x25519", "psk_offered": False, "psk_accepted": False,
             "early_data_offered": False, "tls13": True, "hrr": False,
             "client_hello_bytes": 1, "server_hello_bytes": 1, "encrypted_server_bytes": 1,
             "client_flight_bytes": 1, "server_flight_records": 1}
    assert run_e5.wire_verification([facts] * 3, group="x25519", expected=3)["group_verified"]
    assert not run_e5.wire_verification([facts] * 3, group="X25519MLKEM768", expected=3)["group_verified"]
