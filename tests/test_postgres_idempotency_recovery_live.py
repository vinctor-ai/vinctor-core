from __future__ import annotations

import pytest
from idempotency_postgres_faults import inject_commit_ack_loss
from idempotency_postgres_fixtures import (
    configured_postgres_executor,
    count_rows,
    invocation,
    outcome,
)
from idempotency_postgres_phase01_results import (
    CompletedResultSeed,
    seed_completed_result,
)

from vinctor_service.idempotency_models import (
    IdempotencyProceedToReservation,
    IdempotencyReplayCandidate,
    IdempotencyWriteUnavailable,
)
from vinctor_service.idempotency_storage import HARD_SLOT_LIMIT
from vinctor_service.postgres import connect_postgres


def test_reservation_commit_ack_loss_quarantines_before_callback(
    requires_postgres: str,
) -> None:
    connection, _, executor = configured_postgres_executor(requires_postgres)
    inject_commit_ack_loss(
        connection,
        transaction_boundary=3,
        commit_happened=True,
    )
    callbacks = 0

    def callback():
        nonlocal callbacks
        callbacks += 1
        return outcome()

    with pytest.raises(IdempotencyWriteUnavailable):
        executor.execute(invocation(), callback)

    observer = connect_postgres(requires_postgres)
    try:
        assert connection.is_quarantined is True
        assert callbacks == 0
        assert count_rows(observer, "idempotency_cipher_nonces") == 1
        assert count_rows(observer, "idempotency_results") == 0
    finally:
        observer.close()


def test_fresh_authoritative_lookup_replays_seeded_committed_result(
    requires_postgres: str,
) -> None:
    connection, store, _ = configured_postgres_executor(requires_postgres)
    request = invocation()
    response = outcome().response
    now_epoch = store.database_epoch()
    seed_completed_result(
        connection,
        store,
        CompletedResultSeed(
            request=request,
            response=response,
            created_at_epoch=now_epoch,
            expires_at_epoch=now_epoch + request.max_terminal_ttl_seconds,
        ),
    )
    old_generation = connection.generation
    connection.quarantine_after_ambiguous_commit(old_generation)

    result = store.fresh_authoritative_lookup(
        request,
        now_epoch=now_epoch,
        after_generation=old_generation,
    )

    assert isinstance(result, IdempotencyReplayCandidate)
    assert result.response == response
    assert connection.generation > old_generation


def test_fresh_authoritative_absence_permits_new_reservation_without_callback(
    requires_postgres: str,
) -> None:
    connection, store, _ = configured_postgres_executor(requires_postgres)
    now_epoch = store.database_epoch()
    old_generation = connection.generation
    connection.quarantine_after_ambiguous_commit(old_generation)

    result = store.fresh_authoritative_lookup(
        invocation(),
        now_epoch=now_epoch,
        after_generation=old_generation,
    )
    reservation = store.reserve_nonce(invocation(), now_epoch=now_epoch)

    assert isinstance(result, IdempotencyProceedToReservation)
    assert len(reservation.nonce) == 12
    assert count_rows(connection, "idempotency_results") == 0


def test_quarantine_replaces_physical_generation_without_rebuilding_store(
    requires_postgres: str,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    old_generation = connection.generation
    connection.quarantine_after_ambiguous_commit(old_generation)

    assert connection.execute("SELECT 1").fetchone() == (1,)
    assert connection.generation > old_generation
    assert executor.store is store


def test_readiness_stays_false_until_replacement_passes_all_validators(
    requires_postgres: str,
) -> None:
    connection, store, _ = configured_postgres_executor(requires_postgres)
    connection.quarantine_after_ambiguous_commit(connection.generation)

    assert store.readiness() is False
    assert connection.execute("SELECT 1").fetchone() == (1,)
    connection.rollback()
    assert store.readiness() is True


@pytest.mark.parametrize("commit_happened", (True, False))
def test_barrier_ambiguity_recovers_on_fresh_authority_without_business_result(
    requires_postgres: str,
    commit_happened: bool,
) -> None:
    connection, store, _ = configured_postgres_executor(requires_postgres)
    inject_commit_ack_loss(
        connection,
        transaction_boundary=2,
        commit_happened=commit_happened,
    )

    store.write_disable(version="primary", reason="rotation")
    observer = connect_postgres(requires_postgres)
    try:
        state = observer.execute(
            "SELECT write_disabled_epoch, write_disabled_reason "
            "FROM idempotency_cipher_key_versions WHERE version_label = %s",
            ("primary",),
        ).fetchone()
        assert state is not None
        assert state[0] is not None
        assert state[1] == "rotation"
        assert count_rows(observer, "idempotency_results") == 0
    finally:
        observer.close()


@pytest.mark.parametrize("failure", ("nonce_collision", "hard_limit"))
@pytest.mark.parametrize("commit_happened", (True, False))
def test_emergency_barrier_recovers_exact_state_without_business_effects(
    requires_postgres: str,
    failure: str,
    commit_happened: bool,
) -> None:
    nonce = b"n" * 12
    connection, _, executor = configured_postgres_executor(
        requires_postgres,
        nonce_factory=lambda _: nonce,
    )
    initial_slots = HARD_SLOT_LIMIT if failure == "hard_limit" else 0
    initial_nonces = 1 if failure == "nonce_collision" else 0
    request = invocation()
    with connection.transaction():
        if failure == "hard_limit":
            connection.execute(
                "UPDATE idempotency_cipher_key_versions "
                "SET reserved_encryption_slots = %s WHERE version_label = %s",
                (initial_slots, "primary"),
            )
        else:
            connection.execute(
                "INSERT INTO idempotency_cipher_nonces "
                "(cipher_key_version, slot, nonce, reserved_at_epoch, "
                "workspace_id, principal, operation, key_hash, request_fingerprint) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                ("primary", 1, nonce, 1, *request.reservation_owner_identity),
            )
    inject_commit_ack_loss(
        connection,
        transaction_boundary=4,
        commit_happened=commit_happened,
    )
    callbacks = 0

    def callback():
        nonlocal callbacks
        callbacks += 1
        return outcome()

    with pytest.raises(IdempotencyWriteUnavailable):
        executor.execute(request, callback)

    observer = connect_postgres(requires_postgres)
    try:
        row = observer.execute(
            "SELECT reserved_encryption_slots, write_disabled_epoch, "
            "write_disabled_reason FROM idempotency_cipher_key_versions "
            "WHERE version_label = %s",
            ("primary",),
        ).fetchone()
        assert row is not None
        assert (int(row[0]), row[1] is not None, str(row[2])) == (
            initial_slots,
            True,
            failure,
        )
        assert count_rows(observer, "idempotency_cipher_nonces") == initial_nonces
        assert count_rows(observer, "idempotency_results") == 0
        assert count_rows(observer, "audit_events") == 0
        assert connection.is_quarantined is True
        assert callbacks == 0
    finally:
        observer.close()


def test_incompatible_replacement_is_closed_and_never_published(
    requires_postgres: str,
) -> None:
    connection, store, _ = configured_postgres_executor(requires_postgres)
    with connection.transaction():
        connection.execute(
            "INSERT INTO idempotency_cipher_key_versions "
            "(version_label, key_commitment, reserved_encryption_slots, first_seen_epoch) "
            "VALUES (%s, %s, %s, %s)",
            ("unknown", b"u" * 32, 0, 1),
        )
        connection.execute(
            "INSERT INTO idempotency_results "
            "(workspace_id, principal, operation, key_hash, request_fingerprint, "
            "format_version, status_code, cipher_key_version, response_nonce, "
            "response_ciphertext, created_at_epoch, expires_at_epoch) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                "ws",
                "agent:a",
                "grant.issue.v1",
                b"x" * 32,
                b"f" * 32,
                1,
                201,
                "unknown",
                b"n" * 12,
                b"ciphertext-and-tag",
                1,
                4_102_444_800,
            ),
        )
    old_generation = connection.generation
    connection.quarantine_after_ambiguous_commit(old_generation)

    with pytest.raises(ValueError):
        connection.execute("SELECT 1")

    assert connection.is_quarantined is True
    assert store.readiness() is False
