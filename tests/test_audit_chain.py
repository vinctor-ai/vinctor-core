from vinctor_service.audit_chain import (
    GENESIS_PREV_HASH,
    crosscheck_values_match,
    row_hash,
)


def test_genesis_is_64_hex_zeros() -> None:
    assert GENESIS_PREV_HASH == "0" * 64


def test_row_hash_is_deterministic_and_sha256_hex() -> None:
    h1 = row_hash(1, '{"a":1}', GENESIS_PREV_HASH)
    h2 = row_hash(1, '{"a":1}', GENESIS_PREV_HASH)
    assert h1 == h2
    assert len(h1) == 64 and all(c in "0123456789abcdef" for c in h1)


def test_row_hash_changes_with_any_field() -> None:
    base = row_hash(1, '{"a":1}', GENESIS_PREV_HASH)
    assert row_hash(2, '{"a":1}', GENESIS_PREV_HASH) != base       # seq
    assert row_hash(1, '{"a":2}', GENESIS_PREV_HASH) != base       # content
    assert row_hash(1, '{"a":1}', "f" * 64) != base               # prev_hash


def test_event_class_crosscheck_treats_absent_json_key_as_decision() -> None:
    # to_dict omits event_class when "decision" (and pre-event_class rows never
    # carried it), so an absent JSON field must equal a 'decision' column on a
    # healthy chain — while any other divergence is still a mismatch.
    assert crosscheck_values_match("event_class", None, "decision") is True
    assert crosscheck_values_match("event_class", "control", "control") is True
    assert crosscheck_values_match("event_class", None, "control") is False
    assert crosscheck_values_match("event_class", "control", "decision") is False
