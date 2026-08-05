from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, NewType, Protocol, TypeAlias

IdempotencyKeyVersionLabel = NewType("IdempotencyKeyVersionLabel", str)
IdempotencyKeyCommitment = NewType("IdempotencyKeyCommitment", bytes)
IdempotencyRequestFingerprint = NewType("IdempotencyRequestFingerprint", bytes)


@dataclass(frozen=True, slots=True)
class IdempotencyKeyVersion:
    version: IdempotencyKeyVersionLabel
    material: bytes = field(repr=False)
    commitment: IdempotencyKeyCommitment


@dataclass(frozen=True, slots=True)
class IdempotencyKeyRegistration:
    version: IdempotencyKeyVersionLabel
    commitment: IdempotencyKeyCommitment


@dataclass(frozen=True, slots=True, repr=False)
class RequestFingerprintInput:
    method: str
    path: str
    authenticated_workspace_id: str
    authenticated_principal: str
    operation: str
    request_body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class ResponseAadInput:
    format_version: int
    workspace_id: str
    principal: str
    operation: str
    key_hash: bytes
    request_fingerprint: bytes
    status_code: int
    content_type: str
    cipher_key_version: IdempotencyKeyVersionLabel
    created_at_epoch: int
    expires_at_epoch: int


@dataclass(frozen=True, slots=True, repr=False)
class EncryptedResponseEnvelope:
    format_version: int
    version: IdempotencyKeyVersionLabel
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class IdempotencyInvocation:
    workspace_id: str
    principal: str
    operation: str
    key_hash: bytes = field(repr=False)
    request_fingerprint: bytes = field(repr=False)
    max_terminal_ttl_seconds: int

    @property
    def result_identity(self) -> tuple[str, str, str, bytes]:
        return self.workspace_id, self.principal, self.operation, self.key_hash

    @property
    def reservation_owner_identity(self) -> tuple[str, str, str, bytes, bytes]:
        return (*self.result_identity, self.request_fingerprint)


@dataclass(frozen=True, slots=True)
class HttpResponseObservation:
    error_code: str | None
    decision: str | None


@dataclass(frozen=True, slots=True, repr=False)
class PreSerializedHttpResponse:
    status_code: int
    content_type: Literal["application/json"]
    body: bytes = field(repr=False)
    observation: HttpResponseObservation


@dataclass(frozen=True, slots=True, repr=False)
class CacheableTerminalOutcome:
    response: PreSerializedHttpResponse = field(repr=False)
    replay_not_after_epoch: int | None = None


@dataclass(frozen=True, slots=True, repr=False)
class CryptoReservation:
    version: IdempotencyKeyVersionLabel
    slot: int
    nonce: bytes = field(repr=False)
    reserved_at_epoch: int

    @property
    def ledger_identity(
        self,
    ) -> tuple[IdempotencyKeyVersionLabel, int, bytes, int]:
        return self.version, self.slot, self.nonce, self.reserved_at_epoch


@dataclass(frozen=True, slots=True)
class IdempotencyKeyVersionState:
    version: IdempotencyKeyVersionLabel
    reserved_encryption_slots: int
    first_seen_epoch: int
    soft_limit_reported_epoch: int | None
    write_disabled_epoch: int | None
    write_disabled_reason: str | None
    drain_completed_epoch: int | None
    retired_epoch: int | None


@dataclass(frozen=True, slots=True, repr=False)
class IdempotencyReplayCandidate:
    response: PreSerializedHttpResponse = field(repr=False)


@dataclass(frozen=True, slots=True)
class IdempotencyProceedToReservation:
    pass


IdempotencyLookupResult: TypeAlias = IdempotencyReplayCandidate | IdempotencyProceedToReservation
IdempotencyMutation: TypeAlias = Callable[[], CacheableTerminalOutcome]


class IdempotencyStore(Protocol):
    def database_epoch(self) -> int: ...

    def lookup(
        self,
        invocation: IdempotencyInvocation,
        *,
        now_epoch: int,
    ) -> IdempotencyLookupResult: ...

    def reserve_nonce(
        self,
        invocation: IdempotencyInvocation,
        *,
        now_epoch: int,
    ) -> CryptoReservation: ...

    def complete(
        self,
        invocation: IdempotencyInvocation,
        reservation: CryptoReservation,
        mutation: IdempotencyMutation,
    ) -> PreSerializedHttpResponse: ...


class IdempotentMutationExecutor(Protocol):
    def execute(
        self,
        invocation: IdempotencyInvocation,
        mutation: IdempotencyMutation,
    ) -> PreSerializedHttpResponse: ...


class IdempotencyFingerprintError(ValueError):
    def __str__(self) -> str:
        return "invalid idempotency request fingerprint"


class IdempotencyCipherUnavailableError(ValueError):
    def __str__(self) -> str:
        return "idempotency cipher unavailable"


class IdempotencyKeyringConfigError(ValueError):
    def __str__(self) -> str:
        return "invalid idempotency key configuration"


class IdempotencyConflict(RuntimeError):
    def __str__(self) -> str:
        return "idempotency key conflict"


class AmbiguousCommitError(RuntimeError):
    def __str__(self) -> str:
        return "idempotency unavailable"


class IdempotencyResultUnavailable(RuntimeError):
    def __str__(self) -> str:
        return "idempotency unavailable"


class IdempotencyWriteUnavailable(RuntimeError):
    def __str__(self) -> str:
        return "idempotency unavailable"
