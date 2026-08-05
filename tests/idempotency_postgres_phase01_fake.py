from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TypeAlias

from psycopg import OperationalError

FakeDbValue: TypeAlias = bytes | int | str | None


class FakeConnectionInfo:
    def __init__(self, transaction_status: int) -> None:
        self.transaction_status = transaction_status


class FakeCursor:
    def __init__(self, row: tuple[FakeDbValue, ...] | None) -> None:
        self.row = row

    def fetchone(self) -> tuple[FakeDbValue, ...] | None:
        return self.row


class StatefulPostgresConnection:
    def __init__(
        self,
        *,
        transaction_status: int,
        fail_execute: bool = False,
    ) -> None:
        self.info = FakeConnectionInfo(transaction_status)
        self.fail_execute = fail_execute
        self.executed_sql: list[str] = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False
        self.broken = False

    def execute(
        self,
        query: str,
        _params: tuple[str | bytes | int, ...] | None = None,
    ) -> FakeCursor:
        self.executed_sql.append(query)
        if self.fail_execute:
            self.info.transaction_status = 3
            raise OperationalError
        self.info.transaction_status = 2
        if "clock_timestamp()" in query:
            return FakeCursor((123,))
        if "FROM idempotency_results" in query:
            return FakeCursor(None)
        if "FROM idempotency_cipher_key_versions" in query:
            return FakeCursor((0, 1, None, None, None, None, None))
        raise AssertionError(query)

    def commit(self) -> None:
        self.commits += 1
        self.info.transaction_status = 0

    def rollback(self) -> None:
        self.rollbacks += 1
        self.info.transaction_status = 0

    @contextmanager
    def transaction(self) -> Iterator[None]:
        completed = False
        try:
            yield
            completed = True
        finally:
            if completed:
                self.commit()
            else:
                self.rollback()

    def close(self) -> None:
        self.closed = True
