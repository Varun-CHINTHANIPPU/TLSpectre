from tlslab.analysis_jmh import summarize


def test_jmh_summary_keeps_provider_and_units():
    rows = summarize([{
        "benchmark": "lab.AeadBench.encrypt", "params": {
            "provider": "BC", "aead": "AES-128-GCM", "size": "64"
        },
        "primaryMetric": {"score": 14.0, "scoreError": 0.5, "scoreUnit": "ops/s"},
        "forks": 3,
    }])
    assert rows[0]["size"] == 64
    assert rows[0]["provider"] == "BC"
    assert rows[0]["score_unit"] == "ops/s"
    assert rows[0]["score_error"] == 0.5
