from __future__ import annotations

from dataclasses import dataclass, field
from typing import assert_never

from vinctor_service.idempotency_crypto import (
    ENVELOPE_FORMAT_VERSION,
    build_response_aad,
    encrypt_reserved_response,
)
from vinctor_service.idempotency_keyring import IdempotencyKeyring
from vinctor_service.idempotency_models import (
    CacheableTerminalOutcome,
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyCipherUnavailableError,
    IdempotencyInvocation,
    IdempotencyKeyVersionLabel,
    IdempotencyMutation,
    IdempotencyProceedToReservation,
    IdempotencyReplayCandidate,
    IdempotencyResultUnavailable,
    IdempotencyWriteUnavailable,
    PreSerializedHttpResponse,
    ResponseAadInput,
)
from vinctor_service.idempotency_postgres_recovery import signed_advisory_key
from vinctor_service.idempotency_postgres_result_storage import (
    claim_postgres_reservation,
    delete_postgres_result,
    insert_postgres_result,
    load_postgres_result,
    postgres_database_epoch,
    postgres_result_uses_reservation_nonce,
    require_postgres_reservation_authentic,
)
from vinctor_service.idempotency_storage import (
    JSON_CONTENT_TYPE,
    classify_completed_result,
    encode_response_plaintext,
    parse_completed_result_row,
    terminal_expiry_epoch,
)
from vinctor_service.postgres_connection import SerializedPostgresConnection
from vinctor_service.postgres_driver import PostgresError


@dataclass(frozen=True, slots=True, repr=False)
class PostgresCompletionAttempt:
    invocation: IdempotencyInvocation
    reservation: CryptoReservation
    mutation: IdempotencyMutation = field(repr=False)


class PostgresCompletionMixin:
    conn: SerializedPostgresConnection
    keyring: IdempotencyKeyring | None

    def complete(
        self,
        invocation: IdempotencyInvocation,
        reservation: CryptoReservation,
        mutation: IdempotencyMutation,
    ) -> PreSerializedHttpResponse:
        attempt = PostgresCompletionAttempt(invocation, reservation, mutation)
        try:
            with self.conn.lock:
                if int(self.conn.info.transaction_status) != 0:
                    raise IdempotencyWriteUnavailable
                with self.conn.transaction():
                    now_epoch = postgres_database_epoch(self.conn)
                    record = load_postgres_result(self.conn, invocation)
                    classified = classify_completed_result(
                        invocation,
                        record,
                        self.keyring,
                        now_epoch=now_epoch,
                    )
        except IdempotencyResultUnavailable:
            raise IdempotencyWriteUnavailable from None
        except PostgresError:
            raise IdempotencyResultUnavailable from None
        match classified:
            case IdempotencyReplayCandidate(response=response):
                return response
            case IdempotencyProceedToReservation():
                pass
            case unreachable:
                assert_never(unreachable)
        try:
            with self.conn.lock:
                if int(self.conn.info.transaction_status) != 0:
                    raise IdempotencyWriteUnavailable
                with self.conn.transaction():
                    claim_postgres_reservation(
                        self.conn,
                        invocation,
                        reservation,
                        now_epoch=postgres_database_epoch(self.conn),
                    )
        except PostgresError:
            raise IdempotencyWriteUnavailable from None
        try:
            with self.conn.transaction():
                self.conn.execute(
                    "SELECT pg_advisory_xact_lock(%s)",
                    (
                        signed_advisory_key(
                            invocation.workspace_id,
                            invocation.principal,
                            invocation.operation,
                            invocation.key_hash,
                        ),
                    ),
                )
                return self._complete_in_transaction(attempt)
        except PostgresError:
            raise IdempotencyWriteUnavailable from None

    def gc_expired_results(self, *, limit: int = 100) -> int:
        if not (bounded_limit := max(0, min(limit, 100))):
            return 0
        with self.conn.transaction():
            rows = self.conn.execute(
                "SELECT workspace_id, principal, operation, key_hash,"
                " request_fingerprint, format_version, status_code,"
                " cipher_key_version, response_nonce, response_ciphertext,"
                " created_at_epoch, expires_at_epoch"
                " FROM idempotency_results"
                " WHERE expires_at_epoch <= "
                "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
                " ORDER BY expires_at_epoch, workspace_id, principal, operation, key_hash"
                " FOR UPDATE SKIP LOCKED LIMIT %s",
                (bounded_limit,),
            ).fetchall()
            now_epoch = postgres_database_epoch(self.conn)
            for row in rows:
                invocation, record = parse_completed_result_row(row)
                classified = classify_completed_result(
                    invocation,
                    record,
                    self.keyring,
                    now_epoch=now_epoch,
                )
                match classified:
                    case IdempotencyProceedToReservation():
                        delete_postgres_result(self.conn, invocation)
                    case IdempotencyReplayCandidate():
                        continue
                    case unreachable:
                        assert_never(unreachable)
        return len(rows)

    def _complete_in_transaction(
        self,
        attempt: PostgresCompletionAttempt,
    ) -> PreSerializedHttpResponse:
        claimed_at_epoch = require_postgres_reservation_authentic(
            self.conn,
            attempt.invocation,
            attempt.reservation,
        )
        if claimed_at_epoch is None:
            raise IdempotencyWriteUnavailable
        now_epoch = postgres_database_epoch(self.conn)
        record = load_postgres_result(self.conn, attempt.invocation)
        if postgres_result_uses_reservation_nonce(self.conn, attempt.reservation):
            raise IdempotencyWriteUnavailable
        classified = classify_completed_result(
            attempt.invocation,
            record,
            self.keyring,
            now_epoch=now_epoch,
        )
        match classified:
            case IdempotencyReplayCandidate(response=response):
                return response
            case IdempotencyProceedToReservation():
                if record is not None:
                    delete_postgres_result(self.conn, attempt.invocation)
            case unreachable:
                assert_never(unreachable)

        outcome = attempt.mutation()
        expires_at_epoch = terminal_expiry_epoch(
            attempt.invocation,
            now_epoch=now_epoch,
            replay_not_after_epoch=outcome.replay_not_after_epoch,
        )
        if expires_at_epoch <= now_epoch:
            return outcome.response
        envelope = self._encrypt_outcome(
            attempt,
            outcome,
            now_epoch=now_epoch,
            expires_at_epoch=expires_at_epoch,
        )
        if (
            envelope.nonce != attempt.reservation.nonce
            or envelope.version != attempt.reservation.version
        ):
            raise IdempotencyCipherUnavailableError
        insert_postgres_result(
            self.conn,
            attempt,
            outcome,
            envelope,
            now_epoch=now_epoch,
            expires_at_epoch=expires_at_epoch,
        )
        return outcome.response

    def _encrypt_outcome(
        self,
        attempt: PostgresCompletionAttempt,
        outcome: CacheableTerminalOutcome,
        *,
        now_epoch: int,
        expires_at_epoch: int,
    ) -> EncryptedResponseEnvelope:
        if self.keyring is None:
            raise IdempotencyWriteUnavailable
        key = self.keyring.decryption_key(attempt.reservation.version)
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
        return encrypt_reserved_response(
            key=key,
            reservation=attempt.reservation,
            plaintext=encode_response_plaintext(outcome.response),
            aad=aad,
        )
