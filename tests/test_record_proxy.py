import pytest
from tlslab.record_proxy import mutate


def test_bitflip_alters_only_ciphertext():
    record = b"\x17\x03\x03\x00\x03abc"
    changed = mutate(record, "bitflip")
    assert changed == b"\x17\x03\x03\x00\x03abb"


def test_duplicate_preserves_record():
    record = b"\x17\x03\x03\x00\x01x"
    assert mutate(record, "duplicate") == record * 2


def test_drop_and_truncate_are_distinct():
    record = b"\x17\x03\x03\x00\x08abcdefgh"
    assert mutate(record, "drop") == b""
    truncated = mutate(record, "truncate")
    assert len(truncated) < len(record)
    assert truncated[:5] == record[:5]


def test_unknown_action():
    with pytest.raises(ValueError):
        mutate(b"\x17\x03\x03\x00\x01a", "synthesize")
