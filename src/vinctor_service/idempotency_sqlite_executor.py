from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, assert_never

from vinctor_service.idempotency_models import (
    AmbiguousCommitError,
    IdempotencyInvocation,
    IdempotencyMutation,
    IdempotencyProceedToReservation,
    IdempotencyReplayCandidate,
    IdempotencyWriteUnavailable,
    PreSerializedHttpResponse,
)

if TYPE_CHECKING:
    from vinctor_service.idempotency_sqlite import SQLiteIdempotencyStore


class SQLiteIdempotentMutationExecutor:
    def __init__(
        self,
        store: SQLiteIdempotencyStore,
        *,
        ambiguous_commit_reporter: Callable[[], object] | None = None,
    ) -> None:
        self.store = store
        self._ambiguous_commit_reporter = ambiguous_commit_reporter

    def execute(
        self,
        invocation: IdempotencyInvocation,
        mutation: IdempotencyMutation,
    ) -> PreSerializedHttpResponse:
        try:
            now_epoch = self.store.database_epoch()
            match self.store.lookup(invocation, now_epoch=now_epoch):
                case IdempotencyReplayCandidate(response=response):
                    return response
                case IdempotencyProceedToReservation():
                    reservation = self.store.reserve_nonce(
                        invocation,
                        now_epoch=now_epoch,
                    )
                    return self.store.complete(invocation, reservation, mutation)
                case unreachable:
                    assert_never(unreachable)
        except AmbiguousCommitError:
            try:
                if self._ambiguous_commit_reporter is not None:
                    self._ambiguous_commit_reporter()
            except Exception:
                raise IdempotencyWriteUnavailable from None
            raise IdempotencyWriteUnavailable from None
