from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from queue import Queue
from typing import Any

from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import SerializedSQLiteConnection, connect_sqlite

DEFAULT_SQLITE_POOL_SIZE = 8


@dataclass(frozen=True)
class SQLiteRequestContext:
    connection: SerializedSQLiteConnection
    service: SQLiteV1Service
    key_repository: SQLiteLocalKeyRepository


class _ContextAttributeProxy:
    def __init__(self, pool: SQLiteServicePool, attribute: str) -> None:
        self._pool = pool
        self._attribute = attribute

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._pool.current_context, self._attribute)
        return getattr(target, name)


class SQLiteServicePool:
    """Bounded request-scoped services over independent SQLite connections."""

    def __init__(
        self,
        database: str | Path,
        *,
        primary_connection: SerializedSQLiteConnection,
        primary_service: SQLiteV1Service,
        primary_key_repository: SQLiteLocalKeyRepository,
        size: int = DEFAULT_SQLITE_POOL_SIZE,
    ) -> None:
        if size < 1:
            raise ValueError("SQLite service pool size must be at least 1")
        primary_service.assert_pool_state_contract()

        primary = SQLiteRequestContext(
            connection=primary_connection,
            service=primary_service,
            key_repository=primary_key_repository,
        )
        self._contexts = [primary]
        self._available: Queue[SQLiteRequestContext] = Queue(maxsize=size)
        self._current: ContextVar[SQLiteRequestContext | None] = ContextVar(
            f"vinctor_sqlite_request_context_{id(self)}", default=None
        )
        self._closed = False
        self.service = _ContextAttributeProxy(self, "service")
        self.key_repository = _ContextAttributeProxy(self, "key_repository")

        try:
            for _ in range(size - 1):
                connection = connect_sqlite(database, check_same_thread=False)
                try:
                    service = SQLiteV1Service(
                        connection,
                        initialize_schema=False,
                        shared_state=primary_service.shared_state,
                    )
                    service.assert_pool_state_contract()
                    key_repository = SQLiteLocalKeyRepository(connection)
                except BaseException:
                    connection.close()
                    raise
                self._contexts.append(
                    SQLiteRequestContext(connection, service, key_repository)
                )
        except BaseException:
            self._close_contexts(self._contexts[1:])
            raise

        for context in self._contexts:
            self._available.put_nowait(context)

    @property
    def current_context(self) -> SQLiteRequestContext:
        context = self._current.get()
        if context is None:
            raise RuntimeError("SQLite service proxy used outside a request scope")
        return context

    @property
    def size(self) -> int:
        return len(self._contexts)

    @contextmanager
    def request_scope(self) -> Iterator[None]:
        context = self._available.get()
        token = self._current.set(context)
        try:
            yield
        finally:
            self._current.reset(token)
            if not self._closed:
                self._available.put_nowait(context)

    def is_ready(self) -> bool:
        return self.current_context.connection.execute("SELECT 1").fetchone() == (1,)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        audit_writer = self._contexts[0].service.audit_writer
        close_export = getattr(audit_writer, "close_export", None)
        if callable(close_export):
            close_export()
        self._close_contexts(self._contexts)

    @staticmethod
    def _close_contexts(contexts: list[SQLiteRequestContext]) -> None:
        for context in contexts:
            context.connection.close()
