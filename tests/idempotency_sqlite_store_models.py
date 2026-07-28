from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import (
        CacheableTerminalOutcome,
    )

@dataclass(frozen=True, slots=True)
class ReplayOutcome:
    exact_response: bool
    callback_count: int
    reservations_before: int
    reservations_after: int

@dataclass(frozen=True, slots=True)
class PhaseZeroFailureOutcome:
    typed_error: bool
    callback_count: int
    reservations_before: int
    reservations_after: int
    result_count: int

@dataclass(frozen=True, slots=True)
class ReservationOutcome:
    exit_code: int | None
    reservation_count: int
    nonce_matches: bool

@dataclass(frozen=True, slots=True)
class ProcessRaceOutcome:
    exit_codes: tuple[int | None, ...]
    callback_count: int
    result_count: int

@dataclass(frozen=True, slots=True)
class FirstMissRaceOutcome:
    exit_codes: tuple[int | None, ...]
    callback_count: int
    result_count: int
    reservation_count: int
    distinct_nonce_count: int

@dataclass(frozen=True, slots=True)
class LoserOutcome:
    callback_count: int
    result_count: int
    reservation_count: int

@dataclass(frozen=True, slots=True)
class CollisionOutcome:
    raised: bool
    reserved_slots: int
    disabled_reason: str | None

@dataclass(frozen=True, slots=True)
class SlotBoundaryOutcome:
    soft_reported_epoch: int | None
    hard_limit_raised: bool

@dataclass(frozen=True, slots=True)
class GcOutcome:
    deleted: int
    remaining_results: int

@dataclass(frozen=True, slots=True)
class CompletedResultSeed:
    terminal: CacheableTerminalOutcome
    created_at_epoch: int

@dataclass(frozen=True, slots=True)
class ExpiredHistoricalReuseOutcome:
    unavailable: bool
    callback_count: int
    result_count: int
    reservation_count: int


_RESPONSE_PLAINTEXT_DOMAIN = b"vinctor:idempotency-response-plaintext:v1"
