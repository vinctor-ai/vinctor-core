from __future__ import annotations

import base64
import sqlite3
from pathlib import Path
from types import TracebackType
from typing import cast

import pytest
from idempotency_sqlite_fixtures import (
    audit_event,
    configured_executor,
    count_rows,
    invocation,
    outcome,
)

from vinctor_service import idempotency_sqlite as sqlite_store_module
from vinctor_service.idempotency_keyring import load_idempotency_keyring
from vinctor_service.idempotency_models import (
    AmbiguousCommitError,
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyKeyVersion,
    IdempotencyWriteUnavailable,
)
from vinctor_service.idempotency_sqlite import SQLiteIdempotencyStore
from vinctor_service.sqlite import SQLiteAuditWriter, init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite


@pytest.mark.parametrize("failure_point", ("callback", "audit", "encryption"))
def test_sqlite_failure_after_claim_requires_fresh_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    connection, store, _executor = configured_executor(tmp_path / f"{failure_point}.sqlite")
    owner = invocation()
    writer = SQLiteAuditWriter(connection)
    callbacks: list[str] = []
    encryptions: list[bytes] = []
    real_encrypt = sqlite_store_module.encrypt_response
    real_audit_write = SQLiteAuditWriter.write

    def counted_encrypt(
        *,
        key: IdempotencyKeyVersion,
        reservation: CryptoReservation,
        plaintext: bytes,
        aad: bytes,
    ) -> EncryptedResponseEnvelope:
        encryptions.append(reservation.nonce)
        if failure_point == "encryption":
            raise RuntimeError("forced encryption failure")
        return real_encrypt(
            key=key,
            reservation=reservation,
            plaintext=plaintext,
            aad=aad,
        )

    def failed_mutation():
        callbacks.append("failed")
        connection.execute("INSERT INTO claim_fault_state(value) VALUES ('failed')")
        if failure_point == "callback":
            raise RuntimeError("forced callback failure")
        writer.write(audit_event("evt_claim_fault"))
        return outcome()

    def fail_audit(_writer, _event) -> None:
        raise RuntimeError("forced audit failure")

    monkeypatch.setattr(sqlite_store_module, "encrypt_response", counted_encrypt)
    if failure_point == "audit":
        monkeypatch.setattr(SQLiteAuditWriter, "write", fail_audit)
    try:
        connection.execute("CREATE TABLE claim_fault_state(value TEXT NOT NULL)")
        connection.commit()
        reservation = store.reserve_nonce(owner, now_epoch=100)

        with pytest.raises(RuntimeError, match=f"forced {failure_point} failure"):
            store.complete(owner, reservation, failed_mutation)

        claimed = connection.execute(
            "SELECT claimed_at_epoch FROM idempotency_cipher_nonces "
            "WHERE cipher_key_version = ? AND nonce = ?",
            (reservation.version, reservation.nonce),
        ).fetchone()
        before_retry = (tuple(callbacks), tuple(encryptions))
        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(owner, reservation, failed_mutation)

        assert claimed is not None and claimed[0] is not None
        assert (tuple(callbacks), tuple(encryptions)) == before_retry
        assert count_rows(connection, "claim_fault_state") == 0
        assert count_rows(connection, "audit_events") == 0
        assert count_rows(connection, "idempotency_results") == 0

        monkeypatch.setattr(sqlite_store_module, "encrypt_response", real_encrypt)
        monkeypatch.setattr(SQLiteAuditWriter, "write", real_audit_write)
        fresh = store.reserve_nonce(owner, now_epoch=101)

        def successful_mutation():
            callbacks.append("fresh")
            connection.execute("INSERT INTO claim_fault_state(value) VALUES ('fresh')")
            writer.write(audit_event("evt_claim_fresh"))
            return outcome()

        assert store.complete(owner, fresh, successful_mutation).body == b'{"ok":true}'
        assert fresh.nonce != reservation.nonce
        assert count_rows(connection, "claim_fault_state") == 1
        assert count_rows(connection, "audit_events") == 1
        assert count_rows(connection, "idempotency_results") == 1
    finally:
        connection.close()


class PhaseTwoCommitFailureConnection(sqlite3.Connection):
    fail_before_commit = False

    def commit(self) -> None:
        if self.fail_before_commit:
            self.fail_before_commit = False
            self.rollback()
            raise sqlite3.OperationalError("forced phase two commit failure")
        super().commit()


class ClaimCommitAcknowledgementLostConnection(sqlite3.Connection):
    fail_next_commit_ack = False

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        result = super().__exit__(exc_type, exc, traceback)
        if exc is None and self.fail_next_commit_ack:
            self.fail_next_commit_ack = False
            raise sqlite3.OperationalError("claim commit acknowledgement unavailable")
        return result


def test_sqlite_phase_two_commit_failure_keeps_independent_claim(
    tmp_path: Path,
) -> None:
    database = tmp_path / "commit-failure.sqlite"
    connection = connect_sqlite(database, factory=PhaseTwoCommitFailureConnection)
    raw = cast(PhaseTwoCommitFailureConnection, connection._connection)
    init_sqlite_schema(connection)
    encoded = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{encoded}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    store = SQLiteIdempotencyStore(connection, keyring=keyring)
    owner = invocation()
    callbacks: list[str] = []
    try:
        connection.execute("CREATE TABLE claim_commit_state(value TEXT NOT NULL)")
        connection.commit()
        reservation = store.reserve_nonce(owner, now_epoch=100)

        def failed_mutation():
            callbacks.append("failed")
            connection.execute("INSERT INTO claim_commit_state(value) VALUES ('failed')")
            raw.fail_before_commit = True
            return outcome()

        with pytest.raises(AmbiguousCommitError, match="idempotency unavailable"):
            store.complete(owner, reservation, failed_mutation)

        claimed = connection.execute(
            "SELECT claimed_at_epoch FROM idempotency_cipher_nonces "
            "WHERE cipher_key_version = ? AND nonce = ?",
            (reservation.version, reservation.nonce),
        ).fetchone()
        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(owner, reservation, failed_mutation)

        assert claimed is not None and claimed[0] is not None
        assert callbacks == ["failed"]
        assert count_rows(connection, "claim_commit_state") == 0
        assert count_rows(connection, "idempotency_results") == 0

        fresh = store.reserve_nonce(owner, now_epoch=101)
        assert store.complete(owner, fresh, lambda: outcome()).body == b'{"ok":true}'
    finally:
        connection.close()


def test_sqlite_lost_claim_commit_ack_stays_burned_after_reconnect(
    tmp_path: Path,
) -> None:
    database = tmp_path / "claim-commit-ack.sqlite"
    connection = connect_sqlite(database, factory=ClaimCommitAcknowledgementLostConnection)
    raw = cast(ClaimCommitAcknowledgementLostConnection, connection._connection)
    init_sqlite_schema(connection)
    encoded = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{encoded}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    store = SQLiteIdempotencyStore(connection, keyring=keyring)
    owner = invocation()
    reservation = store.reserve_nonce(owner, now_epoch=100)
    callbacks = 0

    def mutation():
        nonlocal callbacks
        callbacks += 1
        return outcome()

    raw.fail_next_commit_ack = True
    with pytest.raises(AmbiguousCommitError, match="idempotency unavailable"):
        store.complete(owner, reservation, mutation)
    connection.close()

    recovered = connect_sqlite(database)
    recovered_store = SQLiteIdempotencyStore(recovered, keyring=keyring)
    try:
        claimed = recovered.execute(
            "SELECT claimed_at_epoch FROM idempotency_cipher_nonces "
            "WHERE cipher_key_version = ? AND nonce = ?",
            (reservation.version, reservation.nonce),
        ).fetchone()
        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            recovered_store.complete(owner, reservation, mutation)

        assert claimed is not None and claimed[0] is not None
        assert callbacks == 0
        fresh = recovered_store.reserve_nonce(owner, now_epoch=101)
        assert recovered_store.complete(owner, fresh, mutation).body == b'{"ok":true}'
        assert callbacks == 1
    finally:
        recovered.close()
