from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import Protocol, assert_never

from vinctor_service.idempotency_crypto import (
    ENVELOPE_FORMAT_VERSION,
    build_response_aad,
)
from vinctor_service.idempotency_keyring import IdempotencyKeyring
from vinctor_service.idempotency_models import (
    AmbiguousCommitError,
    CacheableTerminalOutcome,
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyCipherUnavailableError,
    IdempotencyInvocation,
    IdempotencyKeyVersion,
    IdempotencyKeyVersionLabel,
    IdempotencyLookupResult,
    IdempotencyMutation,
    IdempotencyProceedToReservation,
    IdempotencyReplayCandidate,
    IdempotencyResultUnavailable,
    IdempotencyWriteUnavailable,
    PreSerializedHttpResponse,
    ResponseAadInput,
)
from vinctor_service.idempotency_sqlite_result_storage import (
    claim_sqlite_reservation,
    delete_sqlite_result,
    insert_sqlite_result,
    load_sqlite_result,
    require_sqlite_reservation_authentic,
    sqlite_database_epoch,
    sqlite_result_uses_reservation_nonce,
)
from vinctor_service.idempotency_storage import (
    JSON_CONTENT_TYPE,
    classify_completed_result,
    encode_response_plaintext,
    parse_completed_result_row,
    terminal_expiry_epoch,
)
from vinctor_service.sqlite_txn import SerializedSQLiteConnection


class ReservedResponseEncryptor(Protocol):
    def __call__(
        self,
        *,
        key: IdempotencyKeyVersion,
        reservation: CryptoReservation,
        plaintext: bytes,
        aad: bytes,
    ) -> EncryptedResponseEnvelope: ...


class SQLiteCompletionStore(Protocol):
    conn: SerializedSQLiteConnection
    keyring: IdempotencyKeyring | None


class ClaimingSQLiteCompletionStore(SQLiteCompletionStore, Protocol):
    def database_epoch(self) -> int: ...

    def lookup(
        self,
        invocation: IdempotencyInvocation,
        *,
        now_epoch: int,
    ) -> IdempotencyLookupResult: ...

    def _transaction(self) -> AbstractContextManager[None]: ...


@dataclass(frozen=True, slots=True, repr=False)
class SQLiteCompletionAttempt:
    invocation: IdempotencyInvocation
    reservation: CryptoReservation
    mutation: IdempotencyMutation = field(repr=False)


def claim_and_complete_sqlite_result(
    store: ClaimingSQLiteCompletionStore,
    attempt: SQLiteCompletionAttempt,
    encrypt: ReservedResponseEncryptor,
) -> PreSerializedHttpResponse:
    try:
        lookup = store.lookup(
            attempt.invocation,
            now_epoch=store.database_epoch(),
        )
    except IdempotencyResultUnavailable:
        raise IdempotencyWriteUnavailable from None
    match lookup:
        case IdempotencyReplayCandidate(response=response):
            return response
        case IdempotencyProceedToReservation():
            pass
        case unreachable:
            assert_never(unreachable)
    try:
        with store._transaction():
            claim_sqlite_reservation(
                store.conn,
                attempt.invocation,
                attempt.reservation,
                now_epoch=sqlite_database_epoch(store.conn),
            )
    except sqlite3.Error:
        raise IdempotencyWriteUnavailable from None
    return complete_sqlite_result(store, attempt, encrypt)


def complete_sqlite_result(
    store: SQLiteCompletionStore,
    attempt: SQLiteCompletionAttempt,
    encrypt: ReservedResponseEncryptor,
) -> PreSerializedHttpResponse:
    from vinctor_service.sqlite import _atomic_write

    body_completed = False
    try:
        with _atomic_write(store.conn):
            response = _complete_in_transaction(store, attempt, encrypt)
            body_completed = True
        return response
    except sqlite3.OperationalError:
        if body_completed:
            raise AmbiguousCommitError from None
        raise IdempotencyWriteUnavailable from None
    except sqlite3.Error:
        raise IdempotencyWriteUnavailable from None


def gc_sqlite_results(store: SQLiteCompletionStore, *, limit: int) -> int:
    from vinctor_service.sqlite import _atomic_write

    bounded_limit = max(0, min(limit, 100))
    if bounded_limit == 0:
        return 0
    with _atomic_write(store.conn):
        now_epoch = sqlite_database_epoch(store.conn)
        rows = store.conn.execute(
            """
            SELECT workspace_id, principal, operation, key_hash,
                   request_fingerprint, format_version, status_code,
                   cipher_key_version, response_nonce, response_ciphertext,
                   created_at_epoch, expires_at_epoch
            FROM idempotency_results
            WHERE expires_at_epoch <= ?
            ORDER BY rowid
            LIMIT ?
            """,
            (now_epoch, bounded_limit),
        ).fetchall()
        for row in rows:
            invocation, record = parse_completed_result_row(row)
            classified = classify_completed_result(
                invocation,
                record,
                store.keyring,
                now_epoch=now_epoch,
            )
            match classified:
                case IdempotencyProceedToReservation():
                    delete_sqlite_result(store.conn, invocation)
                case IdempotencyReplayCandidate():
                    continue
                case unreachable:
                    assert_never(unreachable)
    return len(rows)


def _complete_in_transaction(
    store: SQLiteCompletionStore,
    attempt: SQLiteCompletionAttempt,
    encrypt: ReservedResponseEncryptor,
) -> PreSerializedHttpResponse:
    invocation = attempt.invocation
    reservation = attempt.reservation
    claimed_at_epoch = require_sqlite_reservation_authentic(
        store.conn,
        invocation,
        reservation,
    )
    if claimed_at_epoch is None:
        raise IdempotencyWriteUnavailable
    now_epoch = sqlite_database_epoch(store.conn)
    record = load_sqlite_result(store.conn, invocation)
    if sqlite_result_uses_reservation_nonce(store.conn, reservation):
        raise IdempotencyWriteUnavailable
    classified = classify_completed_result(
        invocation,
        record,
        store.keyring,
        now_epoch=now_epoch,
    )
    match classified:
        case IdempotencyReplayCandidate(response=response):
            return response
        case IdempotencyProceedToReservation():
            if record is not None:
                delete_sqlite_result(store.conn, invocation)
        case unreachable:
            assert_never(unreachable)

    outcome = attempt.mutation()
    expires_at_epoch = terminal_expiry_epoch(
        invocation,
        now_epoch=now_epoch,
        replay_not_after_epoch=outcome.replay_not_after_epoch,
    )
    if expires_at_epoch <= now_epoch:
        return outcome.response
    envelope = _encrypt_outcome(
        store.keyring,
        attempt,
        outcome,
        now_epoch=now_epoch,
        expires_at_epoch=expires_at_epoch,
        encrypt=encrypt,
    )
    if envelope.nonce != reservation.nonce or envelope.version != reservation.version:
        raise IdempotencyCipherUnavailableError
    insert_sqlite_result(
        store.conn,
        attempt,
        outcome,
        envelope,
        now_epoch=now_epoch,
        expires_at_epoch=expires_at_epoch,
    )
    return outcome.response


def _encrypt_outcome(
    keyring: IdempotencyKeyring | None,
    attempt: SQLiteCompletionAttempt,
    outcome: CacheableTerminalOutcome,
    *,
    now_epoch: int,
    expires_at_epoch: int,
    encrypt: ReservedResponseEncryptor,
) -> EncryptedResponseEnvelope:
    if keyring is None:
        raise IdempotencyWriteUnavailable
    key = keyring.decryption_key(attempt.reservation.version)
    if key is None:
        raise IdempotencyWriteUnavailable
    aad = build_response_aad(
        ResponseAadInput(
            format_version=ENVELOPE_FORMAT_VERSION,
            workspace_id=attempt.invocation.workspace_id,
            principal=attempt.invocation.principal,
            operation=attempt.invocation.operation,
            key_hash=attempt.invocation.key_hash,
            request_fingerprint=attempt.invocation.request_fingerprint,
            status_code=outcome.response.status_code,
            content_type=JSON_CONTENT_TYPE,
            cipher_key_version=IdempotencyKeyVersionLabel(attempt.reservation.version),
            created_at_epoch=now_epoch,
            expires_at_epoch=expires_at_epoch,
        )
    )
    return encrypt(
        key=key,
        reservation=attempt.reservation,
        plaintext=encode_response_plaintext(outcome.response),
        aad=aad,
    )
