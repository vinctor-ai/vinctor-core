from __future__ import annotations

from dataclasses import replace

import pytest
from idempotency_postgres_fixtures import (
    audit_event,
    configured_postgres_executor,
    count_rows,
    invocation,
    outcome,
)

from vinctor_service import idempotency_postgres_completion as completion
from vinctor_service.audit import record_rejection
from vinctor_service.idempotency_models import (
    CacheableTerminalOutcome,
    IdempotencyKeyVersionLabel,
    IdempotencyWriteUnavailable,
)

MARKER_TABLE = "idempotency_phase2_business_marker"
PARENT_TABLE = "idempotency_phase2_commit_parent"
REJECT_FUNCTION = "vinctor_phase2_reject_result"
REJECT_TRIGGER = "vinctor_phase2_reject_result"


def _create_marker(connection, *, deferred_foreign_key: bool = False) -> None:
    with connection.transaction():
        connection.execute(f'DROP TABLE IF EXISTS "{MARKER_TABLE}" CASCADE')
        if deferred_foreign_key:
            connection.execute(f'DROP TABLE IF EXISTS "{PARENT_TABLE}" CASCADE')
            connection.execute(f'CREATE TABLE "{PARENT_TABLE}" (value INTEGER PRIMARY KEY)')
            connection.execute(
                f'CREATE TABLE "{MARKER_TABLE}" ('
                "value INTEGER NOT NULL, "
                f'FOREIGN KEY(value) REFERENCES "{PARENT_TABLE}"(value) '
                "DEFERRABLE INITIALLY DEFERRED)"
            )
        else:
            connection.execute(f'CREATE TABLE "{MARKER_TABLE}" (value INTEGER NOT NULL)')


def _drop_fault_objects(connection) -> None:
    with connection.transaction():
        connection.execute(f'DROP TRIGGER IF EXISTS "{REJECT_TRIGGER}" ON idempotency_results')
        connection.execute(f'DROP FUNCTION IF EXISTS "{REJECT_FUNCTION}"()')
        connection.execute(f'DROP TABLE IF EXISTS "{MARKER_TABLE}" CASCADE')
        connection.execute(f'DROP TABLE IF EXISTS "{PARENT_TABLE}" CASCADE')


def _authoritative_mutation(
    connection,
    store,
    event_id: str,
) -> CacheableTerminalOutcome:
    connection.execute(f'INSERT INTO "{MARKER_TABLE}"(value) VALUES (1)')
    store.audit_writer.write(audit_event(event_id))
    return outcome(
        b'{"terminal":"postgres"}',
        error_code="terminal",
        decision="permit",
    )


def _assert_rolled_back(connection, *, audit_rows: int = 0) -> None:
    assert count_rows(connection, MARKER_TABLE) == 0
    assert count_rows(connection, "audit_events") == audit_rows
    assert count_rows(connection, "idempotency_results") == 0
    assert count_rows(connection, "idempotency_cipher_nonces") == 1


def test_postgres_cipher_failure_rolls_back_state_audit_and_result(
    requires_postgres: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    _drop_fault_objects(connection)
    _create_marker(connection)

    def fail_cipher(**_kwargs) -> None:
        raise RuntimeError("cipher fault")

    monkeypatch.setattr(completion, "encrypt_reserved_response", fail_cipher)
    try:
        with pytest.raises(RuntimeError, match="cipher fault"):
            executor.execute(
                invocation(),
                lambda: _authoritative_mutation(
                    connection,
                    store,
                    "evt_postgres_cipher_fault",
                ),
            )
        _assert_rolled_back(connection)
    finally:
        _drop_fault_objects(connection)
        connection.close()


def test_postgres_result_insert_failure_rolls_back_state_audit_and_result(
    requires_postgres: str,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    _drop_fault_objects(connection)
    _create_marker(connection)
    with connection.transaction():
        connection.execute(
            f'CREATE FUNCTION "{REJECT_FUNCTION}"() RETURNS trigger '
            "LANGUAGE plpgsql AS $$ BEGIN "
            "RAISE EXCEPTION 'result insert fault'; END; $$"
        )
        connection.execute(
            f'CREATE TRIGGER "{REJECT_TRIGGER}" '
            "BEFORE INSERT ON idempotency_results "
            f'FOR EACH ROW EXECUTE FUNCTION "{REJECT_FUNCTION}"()'
        )
    try:
        with pytest.raises(IdempotencyWriteUnavailable) as captured:
            executor.execute(
                invocation(),
                lambda: _authoritative_mutation(
                    connection,
                    store,
                    "evt_postgres_result_fault",
                ),
            )
        assert captured.value.__cause__ is None
        _assert_rolled_back(connection)
    finally:
        _drop_fault_objects(connection)
        connection.close()


def test_postgres_commit_failure_rolls_back_state_audit_and_result(
    requires_postgres: str,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    _drop_fault_objects(connection)
    _create_marker(connection, deferred_foreign_key=True)
    try:
        with pytest.raises(IdempotencyWriteUnavailable) as captured:
            executor.execute(
                invocation(),
                lambda: _authoritative_mutation(
                    connection,
                    store,
                    "evt_postgres_commit_fault",
                ),
            )
        assert captured.value.__cause__ is None
        _assert_rolled_back(connection)
    finally:
        _drop_fault_objects(connection)
        connection.close()


def test_postgres_authoritative_failure_rolls_back_callback_state_and_result(
    requires_postgres: str,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    _drop_fault_objects(connection)
    _create_marker(connection)
    event = audit_event("evt_postgres_authoritative_fault")
    store.audit_writer.write(event)
    try:
        with pytest.raises(IdempotencyWriteUnavailable) as captured:
            executor.execute(
                invocation(),
                lambda: _authoritative_mutation(
                    connection,
                    store,
                    event.event_id,
                ),
            )
        assert captured.value.__cause__ is None
        _assert_rolled_back(connection, audit_rows=1)
    finally:
        _drop_fault_objects(connection)
        connection.close()


def test_postgres_best_effort_failure_commits_and_replays_exact_outcome(
    requires_postgres: str,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    _drop_fault_objects(connection)
    _create_marker(connection)
    event = audit_event("evt_postgres_best_effort_fault")
    store.audit_writer.write(event)
    callback_count = 0

    def mutation() -> CacheableTerminalOutcome:
        nonlocal callback_count
        callback_count += 1
        connection.execute(f'INSERT INTO "{MARKER_TABLE}"(value) VALUES (1)')
        assert record_rejection(store.audit_writer, event) is False
        return outcome(
            b'{"terminal":"postgres"}',
            error_code="terminal",
            decision="permit",
        )

    try:
        first = executor.execute(invocation(), mutation)
        replay = executor.execute(
            invocation(),
            lambda: pytest.fail("replay re-entered callback"),
        )
        assert replay == first
        assert callback_count == 1
        assert count_rows(connection, MARKER_TABLE) == 1
        assert count_rows(connection, "audit_events") == 1
        assert count_rows(connection, "idempotency_results") == 1
        assert count_rows(connection, "idempotency_cipher_nonces") == 1
    finally:
        _drop_fault_objects(connection)
        connection.close()


@pytest.mark.parametrize(
    "forgery",
    ("version", "slot", "nonce", "reserved_at_epoch"),
)
def test_postgres_phase_two_rejects_forged_reservation_before_side_effects(
    requires_postgres: str,
    forgery: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, store, _executor = configured_postgres_executor(requires_postgres)
    request = invocation()
    reservation = store.reserve_nonce(request, now_epoch=store.database_epoch())
    replacements = {
        "version": {
            "version": IdempotencyKeyVersionLabel("secondary"),
        },
        "slot": {"slot": reservation.slot + 1},
        "nonce": {"nonce": b"x" * 12},
        "reserved_at_epoch": {
            "reserved_at_epoch": reservation.reserved_at_epoch + 1,
        },
    }
    forged = replace(reservation, **replacements[forgery])
    monkeypatch.setattr(
        completion,
        "encrypt_reserved_response",
        lambda **_kwargs: pytest.fail("forged reservation attempted encryption"),
    )

    try:
        with pytest.raises(IdempotencyWriteUnavailable):
            store.complete(
                request,
                forged,
                lambda: pytest.fail("forged reservation entered callback"),
            )

        assert count_rows(connection, "idempotency_cipher_nonces") == 1
        assert count_rows(connection, "idempotency_results") == 0
        assert count_rows(connection, "audit_events") == 0
    finally:
        connection.close()
