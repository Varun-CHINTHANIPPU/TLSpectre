"""Regressions for the E1 fuzzing-compatibility and calibration fixes."""
from pathlib import Path

import pytest

from tlslab import env, external_probes, probe_protocol, probe_suite
from tlslab.launch import build_command

OK = "sanity ...\nOK\n\n"
SUMMARY = "TOTAL: {t}\nSKIP: 0\nPASS: {p}\nXFAIL: 0\nFAIL: {f}\nXPASS: 0\n"


def failing(name, node, error):
    return (f"{name} ...\nError encountered while processing node {node} (child: None) "
            f"with last message being: None\nError while processing\n"
            f"Traceback (most recent call last):\nAssertionError: {error}\n\n")


def fuzz(monkeypatch, stdout, returncode=1):
    monkeypatch.setattr(external_probes, "tlsfuzzer_script", lambda _: Path("/fake.py"))
    monkeypatch.setattr(external_probes, "run_tool", lambda *a, **k: {
        "status": "OBSERVED", "returncode": returncode, "stderr": "", "stdout": stdout})


def test_tls13_only_fallback_refusals_are_expected(monkeypatch):
    out = (OK + failing("fallback from TLS 1.3-draft40 to 1.2", "ExpectServerHello()",
                        "Unexpected message from peer: Alert(fatal, protocol_version)")
           + failing("TLS 1.3 in client hello legacy field", "ExpectServerHello()",
                     "Unexpected message from peer: Alert(fatal, protocol_version)")
           + OK + SUMMARY.format(t=4, p=2, f=2))
    fuzz(monkeypatch, out)
    seen = external_probes.run_tlsfuzzer("tlsfuzzer_supported_versions", "127.0.0.1", 8443,
                                         profile={"protocols": ["TLSv1.3"]})
    assert seen["status"] == "PASS" and seen["expected_rejections"] == 2


def test_same_refusals_fail_when_tls12_is_enabled(monkeypatch):
    out = (OK + failing("fallback from TLS 1.3-draft40 to 1.2", "ExpectServerHello()",
                        "Unexpected message from peer: Alert(fatal, protocol_version)")
           + failing("fallback from TLS 1.8 to 1.1", "ExpectServerHello()",
                     "Unexpected message from peer: Alert(fatal, protocol_version)")
           + OK + SUMMARY.format(t=4, p=2, f=2))
    fuzz(monkeypatch, out)
    seen = external_probes.run_tlsfuzzer("tlsfuzzer_supported_versions", "127.0.0.1", 8443,
                                         profile={"protocols": ["TLSv1.2", "TLSv1.3"]})
    # TLS 1.1 is disabled, so that refusal is expected; refusing 1.2 is not.
    assert seen["status"] == "FAIL"
    assert seen["expected_rejections"] == 1 and len(seen["unexplained_failures"]) == 1


def test_accepting_malformed_input_is_never_explained_away(monkeypatch):
    out = (OK + failing("fragmented keyupdate msg", "ExpectAlert()",
                        "Unexpected message from peer: ApplicationData(len=529)")
           + failing("large KeyUpdate message", "ExpectAlert(level=2, description=(50,))",
                     'Expected alert description "decode_error" does not match received "illegal_parameter"')
           + OK + SUMMARY.format(t=4, p=2, f=2))
    fuzz(monkeypatch, out)
    seen = external_probes.run_tlsfuzzer("tlsfuzzer_keyupdate", "127.0.0.1", 8443,
                                         profile={"protocols": ["TLSv1.3"]})
    assert seen["status"] == "FAIL"
    assert [u["case"] for u in seen["unexplained_failures"]] == ["fragmented keyupdate msg"]
    assert len(seen["rfc_violations"]) == 1
    assert not seen["nonstandard_rejections"]


def test_parse_disagreement_is_inconclusive(monkeypatch):
    fuzz(monkeypatch, OK + OK + SUMMARY.format(t=5, p=2, f=3))
    seen = external_probes.run_tlsfuzzer("tlsfuzzer_keyupdate", "127.0.0.1", 8443)
    assert seen["status"] == "INCONCLUSIVE"


def test_session_cache_off_disables_both_ticket_mechanisms():
    cmd, _ = build_command(Path("configs/server/A3.yaml"))
    # newSessionTicketCount=0 alone breaks every TLS 1.2 handshake on JDK 27.
    assert "-Djdk.tls.server.newSessionTicketCount=0" in cmd
    assert "-Djdk.tls.server.enableSessionTicketExtension=false" in cmd
    cmd, _ = build_command(Path("configs/server/B1.yaml"))
    assert not any("SessionTicket" in a for a in cmd)


def test_group_enumeration_verdicts(monkeypatch):
    profile = {"namedGroups": ["X25519MLKEM768", "x25519"], "bindHost": "127.0.0.1", "httpsPort": 8443}
    def answer(accepted):
        seen = {g: ("accepted" if g in accepted else "alert:handshake_failure")
                for g in ("x25519", "secp256r1", "ffdhe2048", "x25519mlkem768")}
        return lambda *a: ({"observed": seen, "accepted": sorted(accepted)}, {})
    monkeypatch.setattr(probe_suite, "native_probe", answer({"x25519", "x25519mlkem768"}))
    assert probe_suite.named_group_enumeration(profile)["status"] == "PASS"
    monkeypatch.setattr(probe_suite, "native_probe", answer({"x25519", "x25519mlkem768", "ffdhe2048"}))
    assert probe_suite.named_group_enumeration(profile)["status"] == "FAIL"
    monkeypatch.setattr(probe_suite, "native_probe", answer({"x25519"}))
    assert probe_suite.named_group_enumeration(profile)["status"] == "FAIL"
    assert probe_suite.named_group_enumeration({**profile, "namedGroups": []})["status"] == "N/A"


def test_mutation_expectations_cover_all_four_probes():
    assert set(probe_protocol.MUTATION_EXPECTATION) == {"bitflip", "truncate", "drop", "duplicate"}
    # Only the duplicated record may be served, and only once.
    assert probe_protocol.MUTATION_EXPECTATION["duplicate"] == (1, 0)


def test_client_record_parser_counts_only_complete_records(tmp_path):
    f = tmp_path / "c.tls"
    f.write_bytes(b"\x16\x03\x01\x00\x01A" + b"\x14\x03\x03\x00\x01\x01"
                  + b"\x17\x03\x03\x00\x02BB" + b"\x17\x03\x03\x00\x09short")
    assert probe_protocol._client_records(f) == [22, 20, 23]


def test_no_ticket_means_zero_rtt_impossible(monkeypatch):
    monkeypatch.setattr(probe_protocol, "run_tool", lambda argv, **k: {
        "status": "OBSERVED", "returncode": 0, "stderr": "", "stdout": "HTTP/1.1 200 OK"})
    assert probe_protocol.zero_rtt_probe("127.0.0.1", 8443)["status"] == "PASS"
    monkeypatch.setattr(probe_protocol, "run_tool", lambda argv, **k: {
        "status": "OBSERVED", "returncode": 1, "stderr": "handshake failure", "stdout": ""})
    assert probe_protocol.zero_rtt_probe("127.0.0.1", 8443)["status"] == "BLOCKED"


def test_pcores_found_from_hybrid_pmu_without_core_type(tmp_path, monkeypatch):
    root = tmp_path / "cpu"
    for cpu, core in ((0, 0), (1, 0), (2, 4), (3, 4), (4, 8), (5, 9)):
        d = root / f"cpu{cpu}" / "topology"
        d.mkdir(parents=True)
        (d / "core_id").write_text(str(core))
        (d / "physical_package_id").write_text("0")
    pmu = tmp_path / "cpus"
    pmu.write_text("0-3\n")
    monkeypatch.setattr(env, "CPU_ROOT", root)
    monkeypatch.setattr(env, "PCORE_PMU", pmu)
    assert env.physical_cores() == {0: [0, 1], 2: [2, 3]}
    pmu.unlink()
    with pytest.raises(RuntimeError):
        env.physical_cores()


def test_affinity_verification_rejects_escaped_threads(monkeypatch):
    monkeypatch.setattr(env, "thread_affinities", lambda pid: {"1": [2, 3], "2": [0, 1, 2, 3]})
    with pytest.raises(RuntimeError):
        env.verify_affinity(1, [2, 3])
    monkeypatch.setattr(env, "thread_affinities", lambda pid: {"1": [2, 3], "2": [2]})
    assert env.verify_affinity(1, [2, 3])["all_threads_confined"] is True


def test_e1_probe_subset_rejects_unknown_ids_and_preserves_catalogue_order():
    from tlslab.run_e1 import select_catalogue
    catalogue = [{"id":"PR01"}, {"id":"PR02"}, {"id":"PR03"}]
    assert [x["id"] for x in select_catalogue(catalogue, "PR03,PR01")] == ["PR01", "PR03"]
    for bad in ("PR77", "PR01,PR01", ","):
        with pytest.raises(ValueError):
            select_catalogue(catalogue, bad)

def test_e5_p95_p99_are_actual_percentiles_not_floor_indices():
    from tlslab.run_e5 import latency_percentiles
    p95, p99 = latency_percentiles([1., 2., 3., 4., 5., 6., 7., 8.])
    assert p95 == pytest.approx(7.65)
    assert p99 == pytest.approx(7.93)
    with pytest.raises(ValueError):
        latency_percentiles([])


def test_running_server_refuses_stale_listener(tmp_path):
    import socket
    from tlslab.experiment_control import running_server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        used = listener.getsockname()[1]
        profile = tmp_path / "P1.yaml"
        profile.write_text(
            f"bindHost: 127.0.0.1\nhttpsPort: {used}\nhttpPort: 8080\n"
            "provider: SunJSSE\nprotocols: [TLSv1.3]\n")
        # No JVM should ever be launched when an old server owns 8443.
        with pytest.raises(RuntimeError, match="already listening"):
            with running_server(profile, tmp_path/"server.log"):
                pass


def test_e6_openssl4_tls13_no_staple_is_not_unknown():
    from tlslab.run_e6 import parse_staple_output
    assert parse_staple_output(
        "Connecting to 127.0.0.1\nOCSP responses: no responses sent\n"
    ) == (False, "none")
    assert parse_staple_output(
        "OCSP response: no response sent\n"
    ) == (False, "none")
    assert parse_staple_output(
        "OCSP response: no OCSP response received\n"
    ) == (False, "none")
    assert parse_staple_output(
        "OCSP Response Status: successful (0x0)\nCert Status: good\n"
    ) == (True, "good")
    assert parse_staple_output(
        "OCSP Response Status: successful (0x0)\nCert Status: revoked\n"
    ) == (True, "revoked")
    assert parse_staple_output(
        "verify error:num=23:certificate revoked\n"
    ) == (None, "UNKNOWN")


def test_keyupdate_length_alerts_are_rfc_violations(monkeypatch):
    out = (
        OK
        + failing("empty KeyUpdate message", "ExpectAlert(level=2, description=(50,))",
                  'Expected alert description "decode_error" does not match received "illegal_parameter"')
        + failing("large KeyUpdate message", "ExpectAlert(level=2, description=(50,))",
                  'Expected alert description "decode_error" does not match received "illegal_parameter"')
        + failing("two KeyUpdates in one record", "ExpectNewSessionTicket()",
                  "Unexpected message from peer: Handshake(key_update)")
        + OK
        + SUMMARY.format(t=5, p=2, f=3)
    )
    fuzz(monkeypatch, out)
    seen = external_probes.run_tlsfuzzer(
        "tlsfuzzer_keyupdate", "127.0.0.1", 8443,
        profile={"protocols": ["TLSv1.3"]},
    )
    assert seen["status"] == "FAIL"
    assert {x["case"] for x in seen["rfc_violations"]} == {
        "empty KeyUpdate message", "large KeyUpdate message"
    }
    assert [x["case"] for x in seen["nonstandard_rejections"]] == [
        "two KeyUpdates in one record"
    ]


def test_unknown_keyupdate_alert_mismatch_remains_inconclusive(monkeypatch):
    out = (
        OK
        + failing("unknown malformed KeyUpdate", "ExpectAlert()",
                  'Expected alert description "decode_error" does not match received "illegal_parameter"')
        + OK
        + SUMMARY.format(t=3, p=2, f=1)
    )
    fuzz(monkeypatch, out)
    seen = external_probes.run_tlsfuzzer(
        "tlsfuzzer_keyupdate", "127.0.0.1", 8443,
        profile={"protocols": ["TLSv1.3"]},
    )
    assert seen["status"] == "INCONCLUSIVE"
    assert seen["rfc_violations"] == []
