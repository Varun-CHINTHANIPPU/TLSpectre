from pathlib import Path
from tlslab.launch import ROOT


def test_namespace_preflight_guard():
    text=(ROOT/"harness/tlslab/netns.py").read_text()
    assert "Refusing to alter pre-existing namespaces" in text
    assert "Refusing to replace existing interface" in text


def test_e3_never_fabricates_process_cpu_from_wall_throughput():
    from tlslab.run_e3 import fork_rows
    raw={"params":{},
         "primaryMetric":{"scoreUnit":"ops/s","rawData":[[200.0]]}}
    c={"suite":"TLS_AES_128_GCM_SHA256","size":64,"platform":"SunJCE"}
    row=fork_rows(raw,c)[0]
    assert row["cpu_ns_per_byte"] is None
    assert row["wall_ns_per_byte"]>0
