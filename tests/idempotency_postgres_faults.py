from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from psycopg import OperationalError

from vinctor_service.postgres_connection import SerializedPostgresConnection


def inject_commit_ack_loss(
    connection: SerializedPostgresConnection,
    *,
    transaction_boundary: int,
    commit_happened: bool,
) -> None:
    physical = connection._connection
    boundary = 0
    injected = False

    class PreventCommit(Exception):
        pass

    class CommitAckLossProxy:
        def __getattr__(self, name: str) -> Any:
            return getattr(physical, name)

        @contextmanager
        def transaction(self) -> Iterator[None]:
            nonlocal boundary, injected
            boundary += 1
            selected = not injected and boundary == transaction_boundary
            if selected and not commit_happened:
                try:
                    with physical.transaction():
                        yield
                        raise PreventCommit
                except PreventCommit:
                    injected = True
                    raise OperationalError("commit acknowledgement unavailable") from None
                return
            with physical.transaction():
                yield
            if selected:
                injected = True
                raise OperationalError("commit acknowledgement unavailable")

    connection._connection = CommitAckLossProxy()
