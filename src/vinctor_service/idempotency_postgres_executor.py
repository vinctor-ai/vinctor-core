from __future__ import annotations

from typing import assert_never

from vinctor_service.idempotency_models import (
    AmbiguousCommitError,
    IdempotencyInvocation,
    IdempotencyMutation,
    IdempotencyProceedToReservation,
    IdempotencyReplayCandidate,
    IdempotencyStore,
    IdempotencyWriteUnavailable,
    PreSerializedHttpResponse,
)


class PostgresIdempotentMutationExecutor:
    def __init__(self, store: IdempotencyStore) -> None:
        self.store = store

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
            raise IdempotencyWriteUnavailable from None
