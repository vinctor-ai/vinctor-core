from vinctor_service.audit_chain import GENESIS_PREV_HASH, row_hash


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
