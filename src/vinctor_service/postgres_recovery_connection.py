from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from vinctor_service.idempotency_models import AmbiguousCommitError


def validate_replacement_candidate(
    candidate: Any,
    validators: tuple[Callable[[Any], None], ...],
) -> None:
    with candidate.transaction():
        if candidate.execute("SELECT 1").fetchone() != (1,):
            raise RuntimeError("PostgreSQL replacement readiness check failed")
        for validator in validators:
            validator(candidate)


@contextmanager
def one_shot_authoritative_recovery(
    reconnect: Callable[[], Any],
    ambiguous_commit_errors: tuple[type[Exception], ...],
    compatibility_validators: tuple[Callable[[Any], None], ...],
) -> Iterator[Any]:
    candidate = reconnect()
    try:
        validate_replacement_candidate(candidate, compatibility_validators)
        body_completed = False
        try:
            with candidate.transaction():
                yield candidate
                body_completed = True
        except BaseException as exc:
            if body_completed and isinstance(exc, ambiguous_commit_errors):
                raise AmbiguousCommitError from None
            raise
    finally:
        candidate.close()
