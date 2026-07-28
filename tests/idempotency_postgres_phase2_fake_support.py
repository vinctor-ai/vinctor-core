from __future__ import annotations

import base64
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import cast

from idempotency_postgres_fixtures import invocation
from psycopg import OperationalError

from vinctor_service.idempotency_keyring import (
    IdempotencyKeyring,
    load_idempotency_keyring,
)
from vinctor_service.idempotency_models import (
    CryptoReservation,
    IdempotencyKeyVersionLabel,
)
from vinctor_service.idempotency_postgres_completion import PostgresCompletionMixin
from vinctor_service.postgres_connection import SerializedPostgresConnection


class FakeCursor:
    def __init__(
        self,
        row: tuple[object, ...] | None,
        *,
        rowcount: int = 0,
        rows: list[tuple[object, ...]] | None = None,
    ) -> None:
        self.row = row
        self.rowcount = rowcount
        self.rows = rows or []

    def fetchone(self) -> tuple[object, ...] | None:
        return self.row

    def fetchall(self) -> list[tuple[object, ...]]:
        return self.rows


class FakePostgresConnection:
    def __init__(self) -> None:
        self.queries: list[str] = []
        self.result_rows: dict[tuple[object, ...], tuple[object, ...]] = {}
        self.key_state: tuple[int | None, int | None] = (None, None)
        self.reservation = (
            "primary",
            1,
            b"n" * 12,
            99,
            *invocation().reservation_owner_identity,
        )
        self.reservation_claimed_at_epoch: int | None = None
        self.transaction_depth = 0
        self.fail_result_insert = False
        self.lock = threading.RLock()
        self.info = self

    @property
    def transaction_status(self) -> int:
        return int(self.transaction_depth > 0)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.transaction_depth += 1
        try:
            yield
        finally:
            self.transaction_depth -= 1

    def execute(
        self,
        query: str,
        params: tuple[object, ...] | None = None,
    ) -> FakeCursor:
        self.queries.append(query)
        if "pg_advisory_xact_lock" in query:
            return FakeCursor(None)
        if "FROM idempotency_cipher_nonces AS nonces" in query:
            row = (*self.key_state, self.reservation_claimed_at_epoch)
            return FakeCursor(row if params == self.reservation else None)
        if (
            "FROM idempotency_results" in query
            and "FOR UPDATE SKIP LOCKED" in query
        ):
            assert params == (100,)
            return FakeCursor(None, rows=[(None,)] * 100)
        if "clock_timestamp()" in query and not query.startswith("WITH"):
            return FakeCursor((100,))
        if query.startswith("SELECT 1 FROM idempotency_results"):
            assert params is not None
            version, nonce = params
            used = any(row[3] == version and row[4] == nonce for row in self.result_rows.values())
            return FakeCursor((1,) if used else None)
        if query.startswith("SELECT request_fingerprint"):
            assert params is not None
            return FakeCursor(self.result_rows.get(tuple(params)))
        if query.startswith("UPDATE idempotency_cipher_nonces AS nonces"):
            assert params is not None
            version, nonce = params[1], params[3]
            nonce_unused = not any(
                row[3] == version and row[4] == nonce for row in self.result_rows.values()
            )
            claimed = (
                tuple(params[1:]) == self.reservation
                and self.reservation_claimed_at_epoch is None
                and self.key_state == (None, None)
                and nonce_unused
            )
            if claimed:
                self.reservation_claimed_at_epoch = int(params[0])
            return FakeCursor(None, rowcount=int(claimed))
        if query.startswith("DELETE FROM idempotency_results"):
            assert params is not None
            deleted = self.result_rows.pop(tuple(params), None)
            return FakeCursor(None, rowcount=int(deleted is not None))
        if query.startswith("INSERT INTO idempotency_results"):
            if self.fail_result_insert:
                raise OperationalError("forced result insert failure")
            assert params is not None
            self.result_rows[tuple(params[:4])] = (
                params[4],
                params[5],
                params[6],
                params[7],
                params[8],
                params[9],
                params[10],
                params[11],
            )
            return FakeCursor(None, rowcount=1)
        if query.startswith("WITH doomed AS"):
            assert params == (100,)
            return FakeCursor(None, rowcount=100)
        raise AssertionError(query)


class FakeStore(PostgresCompletionMixin):
    def __init__(self, keyring: IdempotencyKeyring) -> None:
        self.conn = cast(SerializedPostgresConnection, FakePostgresConnection())
        self.keyring = keyring

    @property
    def fake_connection(self) -> FakePostgresConnection:
        return cast(FakePostgresConnection, self.conn)


def keyring() -> IdempotencyKeyring:
    encoded = base64.b64encode(b"k" * 32).decode("ascii")
    loaded = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{encoded}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    assert loaded is not None
    return loaded


def reservation() -> CryptoReservation:
    return CryptoReservation(
        version=IdempotencyKeyVersionLabel("primary"),
        slot=1,
        nonce=b"n" * 12,
        reserved_at_epoch=99,
    )
