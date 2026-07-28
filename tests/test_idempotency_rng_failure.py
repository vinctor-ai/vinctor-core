from __future__ import annotations

import base64
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest
from idempotency_http_header_scenarios import VALID_GRANT_BODY
from idempotency_http_memory_transport import post_memory_raw_json
from idempotency_postgres_fixtures import invocation as postgres_invocation
from idempotency_postgres_fixtures import outcome as postgres_outcome
from idempotency_postgres_phase01_results import phase_zero_counts
from idempotency_sqlite_fixtures import configured_executor, count_rows, invocation, outcome
from idempotency_sqlite_http_scenarios import (
    configured_sqlite_service,
    persisted_counts,
    seed_success_routes,
)

from vinctor_service.idempotency_keyring import load_idempotency_keyring
from vinctor_service.idempotency_models import IdempotencyWriteUnavailable
from vinctor_service.idempotency_postgres import (
    PostgresIdempotencyStore,
    PostgresIdempotentMutationExecutor,
)


def _entropy_failure(_size: int) -> bytes:
    raise OSError("rng failure detail must not cross the boundary")


def test_sqlite_entropy_failure_is_typed_and_rolls_back_phase_one(
    tmp_path: Path,
) -> None:
    # Given a real SQLite executor whose entropy source is unavailable.
    connection, store, executor = configured_executor(
        tmp_path / "entropy.sqlite3",
        nonce_factory=_entropy_failure,
    )
    callback_calls = 0
    before_state = store.key_version_state("primary")
    before_counts = (
        count_rows(connection, "idempotency_cipher_nonces"),
        count_rows(connection, "idempotency_results"),
        count_rows(connection, "audit_events"),
    )

    def mutation():
        nonlocal callback_calls
        callback_calls += 1
        return outcome()

    try:
        # When the first keyed mutation reaches Phase 1 reservation.
        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            executor.execute(invocation(), mutation)

        # Then it emits no durable work and the connection remains usable.
        after_state = store.key_version_state("primary")
        after_counts = (
            count_rows(connection, "idempotency_cipher_nonces"),
            count_rows(connection, "idempotency_results"),
            count_rows(connection, "audit_events"),
        )
        assert callback_calls == 0
        assert after_counts == before_counts == (0, 0, 0)
        assert after_state.reserved_encryption_slots == before_state.reserved_encryption_slots == 0
        assert connection.execute("SELECT 1").fetchone() == (1,)
    finally:
        connection.close()


@dataclass(slots=True)
class _FakePostgresInfo:
    transaction_status: int = 0


@dataclass(frozen=True, slots=True)
class _FakePostgresCursor:
    row: tuple[int, ...] | None

    def fetchone(self) -> tuple[int, ...] | None:
        return self.row


class _RollbackTrackingPostgresConnection:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.info = _FakePostgresInfo()
        self.reserved_slots = 0
        self.nonce_inserts = 0
        self.result_rows = 0
        self.audit_rows = 0

    def add_replacement_validator(self, _validator) -> None:
        return None

    def add_readiness_validator(self, _validator) -> None:
        return None

    @contextmanager
    def transaction(self) -> Iterator[None]:
        previous_slots = self.reserved_slots
        self.info.transaction_status = 2
        try:
            yield
        except (IdempotencyWriteUnavailable, OSError):
            self.reserved_slots = previous_slots
            raise
        finally:
            self.info.transaction_status = 0

    def execute(self, query: str, _params=None) -> _FakePostgresCursor:
        if "clock_timestamp()" in query:
            return _FakePostgresCursor((100,))
        if "FROM idempotency_results" in query:
            return _FakePostgresCursor(None)
        if "SET reserved_encryption_slots = reserved_encryption_slots + 1" in query:
            self.reserved_slots += 1
            return _FakePostgresCursor((self.reserved_slots,))
        if "INSERT INTO idempotency_cipher_nonces" in query:
            self.nonce_inserts += 1
            return _FakePostgresCursor((1,))
        raise AssertionError(query)


def _keyring():
    encoded = base64.b64encode(b"k" * 32).decode("ascii")
    loaded = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{encoded}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    assert loaded is not None
    return loaded


def test_postgres_fake_entropy_failure_is_typed_and_rolls_back_phase_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a rollback-tracking PostgreSQL carrier and an unavailable entropy source.
    connection = _RollbackTrackingPostgresConnection()
    monkeypatch.setattr(PostgresIdempotencyStore, "_register_keyring", lambda _store: None)
    store = PostgresIdempotencyStore(
        connection,
        keyring=None,
        nonce_factory=_entropy_failure,
    )
    store.keyring = _keyring()
    executor = PostgresIdempotentMutationExecutor(store)
    callback_calls = 0

    def mutation():
        nonlocal callback_calls
        callback_calls += 1
        return postgres_outcome()

    # When the PostgreSQL Phase 1 path requests entropy.
    with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
        executor.execute(postgres_invocation(), mutation)

    # Then it rolls back the slot and remains reusable without a callback or result work.
    assert callback_calls == 0
    assert connection.reserved_slots == 0
    assert connection.nonce_inserts == connection.result_rows == connection.audit_rows == 0
    assert store.database_epoch() == 100


def test_postgres_live_entropy_failure_is_typed_and_rolls_back_phase_one(
    requires_postgres: str,
) -> None:
    # Given a live PostgreSQL store whose entropy source fails.
    from idempotency_postgres_fixtures import configured_postgres_executor

    connection, store, executor = configured_postgres_executor(
        requires_postgres,
        nonce_factory=_entropy_failure,
    )
    callback_calls = 0
    before_state = store.key_version_state("primary")
    before_counts = phase_zero_counts(connection)

    def mutation():
        nonlocal callback_calls
        callback_calls += 1
        return postgres_outcome()

    try:
        # When the first keyed mutation reaches durable reservation.
        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            executor.execute(postgres_invocation(), mutation)

        # Then no nonce/result/audit survives, the slot is unchanged, and the connection works.
        after_state = store.key_version_state("primary")
        assert callback_calls == 0
        assert phase_zero_counts(connection) == before_counts
        assert after_state.reserved_encryption_slots == before_state.reserved_encryption_slots == 0
        assert connection.execute("SELECT 1").fetchone() == (1,)
        connection.rollback()
    finally:
        connection.close()


def test_raw_http_entropy_failure_is_coarse_and_has_no_side_effects(tmp_path: Path) -> None:
    # Given a real SQLite HTTP service whose Phase 1 nonce source fails with private detail.
    service, connection = configured_sqlite_service(tmp_path / "http-entropy.sqlite3")
    seed_success_routes(service)
    store = service.idempotency_executor.store
    store.nonce_factory = _entropy_failure
    before_counts = persisted_counts(connection)
    before_state = store.key_version_state("primary")
    try:
        # When a raw keyed POST traverses the HTTP handler.
        response = post_memory_raw_json(
            service,
            "/v1/grants",
            VALID_GRANT_BODY,
            (
                ("X-Workspace-Key", "workspace_key_main"),
                ("Idempotency-Key", "entropy-failure"),
            ),
        )

        # Then the client receives only the coarse 503 while all durable state is unchanged.
        assert response.status_code == 503
        assert response.body == (
            b'{"error": "idempotency_unavailable", "reason": "idempotency_unavailable"}'
        )
        assert b"rng failure" not in response.body
        assert persisted_counts(connection) == before_counts
        assert store.key_version_state("primary") == before_state
        assert connection.execute("SELECT 1").fetchone() == (1,)
    finally:
        connection.close()
