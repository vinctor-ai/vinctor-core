from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, TypeAlias

from vinctor_service.idempotency_keyring import IdempotencyKeyring
from vinctor_service.idempotency_lifecycle import (
    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
    IdempotencyLifecycleRejected,
    IdempotencyLifecycleUnavailable,
)
from vinctor_service.idempotency_lifecycle_postgres_lock import (
    PostgresWriterAttestation,
)
from vinctor_service.idempotency_models import IdempotencyResultUnavailable
from vinctor_service.idempotency_storage import (
    authenticate_completed_result,
    parse_completed_result_row,
)
from vinctor_service.postgres_connection import (
    PostgresConnectionUnavailable,
    SerializedPostgresConnection,
)
from vinctor_service.postgres_driver import PostgresError

DatabaseValue: TypeAlias = str | int | bool | bytes | None


class _QueryResult(Protocol):
    def fetchone(self) -> Sequence[DatabaseValue] | None: ...

    def fetchall(self) -> list[Sequence[DatabaseValue]]: ...


class _RawAuthority(Protocol):
    def execute(
        self,
        query: str,
        params: Sequence[DatabaseValue] = (),
    ) -> _QueryResult: ...


@dataclass(frozen=True, slots=True)
class _DrainStateRow:
    drain_completed_epoch: int | None


@dataclass(frozen=True, slots=True)
class _RetirementStateRow:
    drain_completed_epoch: int | None
    retired_epoch: int | None


@dataclass(frozen=True, slots=True)
class _RetirementOutcome:
    retired_epoch: int | None
    unexpired_results_remain: bool


class _RecoveryAuthorityAdapter:
    __slots__ = ("_authority",)

    def __init__(self, authority: _RawAuthority) -> None:
        self._authority = authority

    def drain_state(self, version: str) -> _DrainStateRow | None:
        row = self._authority.execute(
            "SELECT drain_completed_epoch FROM idempotency_cipher_key_versions "
            "WHERE version_label = %s",
            (version,),
        ).fetchone()
        if row is None:
            return None
        return _DrainStateRow(_optional_int(row[0]))

    def retirement_state(self, version: str) -> _RetirementStateRow | None:
        row = self._authority.execute(
            "SELECT drain_completed_epoch, retired_epoch "
            "FROM idempotency_cipher_key_versions WHERE version_label = %s",
            (version,),
        ).fetchone()
        if row is None:
            return None
        return _RetirementStateRow(
            drain_completed_epoch=_optional_int(row[0]),
            retired_epoch=_optional_int(row[1]),
        )

    def complete_drain(self, version: str) -> _DrainStateRow | None:
        row = self._authority.execute(
            "UPDATE idempotency_cipher_key_versions "
            "SET drain_completed_epoch = COALESCE("
            "drain_completed_epoch, "
            "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
            ") WHERE version_label = %s "
            "AND write_disabled_epoch IS NOT NULL "
            "AND retired_epoch IS NULL "
            "RETURNING drain_completed_epoch",
            (version,),
        ).fetchone()
        if row is None:
            return None
        return _DrainStateRow(_optional_int(row[0]))

    def retire_if_eligible(
        self,
        version: str,
        *,
        active_version: str,
        keyring: IdempotencyKeyring,
    ) -> _RetirementOutcome:
        now_row = self._authority.execute(
            "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
        ).fetchone()
        if now_row is None:
            raise IdempotencyLifecycleUnavailable
        now_epoch = _required_int(now_row[0])
        result_rows = self._authority.execute(
            "SELECT workspace_id, principal, operation, key_hash, "
            "request_fingerprint, format_version, status_code, "
            "cipher_key_version, response_nonce, response_ciphertext, "
            "created_at_epoch, expires_at_epoch FROM idempotency_results "
            "WHERE cipher_key_version = %s "
            "ORDER BY workspace_id, principal, operation, key_hash FOR UPDATE",
            (version,),
        ).fetchall()
        try:
            parsed_results = tuple(
                parse_completed_result_row(result_row) for result_row in result_rows
            )
            if any(record.expires_at_epoch > now_epoch for _, record in parsed_results):
                return _RetirementOutcome(
                    retired_epoch=None,
                    unexpired_results_remain=True,
                )
            for invocation, record in parsed_results:
                authenticate_completed_result(invocation, record, keyring)
                self._authority.execute(
                    "DELETE FROM idempotency_results "
                    "WHERE workspace_id = %s AND principal = %s "
                    "AND operation = %s AND key_hash = %s",
                    invocation.result_identity,
                )
        except IdempotencyResultUnavailable:
            raise IdempotencyLifecycleUnavailable from None
        row = self._authority.execute(
            "UPDATE idempotency_cipher_key_versions AS retiring "
            "SET retired_epoch = COALESCE("
            "retiring.retired_epoch, %s"
            ") "
            "WHERE retiring.version_label = %s "
            "AND retiring.write_disabled_epoch IS NOT NULL "
            "AND retiring.drain_completed_epoch IS NOT NULL "
            "AND retiring.drain_completed_epoch + %s <= %s "
            "AND NOT EXISTS ("
            "SELECT 1 FROM idempotency_results "
            "WHERE cipher_key_version = retiring.version_label"
            ") AND EXISTS ("
            "SELECT 1 FROM idempotency_cipher_key_versions AS active "
            "WHERE active.version_label = %s "
            "AND active.write_disabled_epoch IS NULL "
            "AND active.retired_epoch IS NULL"
            ") RETURNING retiring.retired_epoch",
            (
                now_epoch,
                version,
                IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
                now_epoch,
                active_version,
            ),
        ).fetchone()
        if row is None:
            return _RetirementOutcome(
                retired_epoch=None,
                unexpired_results_remain=False,
            )
        return _RetirementOutcome(
            retired_epoch=_required_int(row[0]),
            unexpired_results_remain=False,
        )


class PostgresLifecycleRecovery:
    __slots__ = ("_conn", "_keyring")

    def __init__(
        self,
        conn: SerializedPostgresConnection,
        keyring: IdempotencyKeyring,
    ) -> None:
        self._conn = conn
        self._keyring = keyring

    def drain(
        self,
        version: str,
        *,
        generation: int,
    ) -> None:
        try:
            with (
                self._conn.fresh_authoritative_recovery(
                    after_generation=generation
                ) as raw_authority,
                PostgresWriterAttestation(
                    raw_authority,
                    version,
                ).exclusive_guard(),
            ):
                authority = _RecoveryAuthorityAdapter(raw_authority)
                state = authority.drain_state(version)
                if state is None:
                    raise IdempotencyLifecycleUnavailable
                if state.drain_completed_epoch is not None:
                    return
                if authority.complete_drain(version) is None:
                    raise IdempotencyLifecycleUnavailable
        except (PostgresError, PostgresConnectionUnavailable):
            raise IdempotencyLifecycleUnavailable from None

    def retire(self, version: str, *, generation: int) -> None:
        unexpired_results_remain = False
        try:
            with (
                self._conn.fresh_authoritative_recovery(
                    after_generation=generation
                ) as raw_authority,
                PostgresWriterAttestation(
                    raw_authority,
                    version,
                ).exclusive_guard(),
            ):
                authority = _RecoveryAuthorityAdapter(raw_authority)
                state = authority.retirement_state(version)
                if state is None:
                    raise IdempotencyLifecycleUnavailable
                if state.retired_epoch is not None:
                    return
                outcome = authority.retire_if_eligible(
                    version,
                    active_version=self._keyring.active_version,
                    keyring=self._keyring,
                )
                if outcome.unexpired_results_remain:
                    unexpired_results_remain = True
                elif outcome.retired_epoch is None:
                    raise IdempotencyLifecycleUnavailable
        except (PostgresError, PostgresConnectionUnavailable):
            raise IdempotencyLifecycleUnavailable from None
        if unexpired_results_remain:
            raise IdempotencyLifecycleRejected("unexpired_results_remain")


def _optional_int(value: DatabaseValue) -> int | None:
    if value is None:
        return None
    return int(value)


def _required_int(value: DatabaseValue) -> int:
    if value is None:
        raise IdempotencyLifecycleUnavailable
    return int(value)
