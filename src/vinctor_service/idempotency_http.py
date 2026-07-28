from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final, Protocol, runtime_checkable

from vinctor_service import idempotency_crypto
from vinctor_service.idempotency_models import (
    AmbiguousCommitError,
    CacheableTerminalOutcome,
    HttpResponseObservation,
    IdempotencyCipherUnavailableError,
    IdempotencyConflict,
    IdempotencyFingerprintError,
    IdempotencyInvocation,
    IdempotencyMutation,
    IdempotencyResultUnavailable,
    IdempotencyWriteUnavailable,
    PreSerializedHttpResponse,
    RequestFingerprintInput,
)
from vinctor_service.v1_http import V1HttpResponse

_KEY_PATTERN: Final = re.compile(r"[A-Za-z0-9._~-]{1,128}\Z")
_CONTENT_TYPE: Final = "application/json"
_MAX_TERMINAL_TTL_SECONDS: Final = 86_400
_LOGGER: Final = logging.getLogger(__name__)


class InvalidIdempotencyKey(ValueError):
    def __str__(self) -> str:
        return "invalid idempotency key"


@dataclass(frozen=True, slots=True, repr=False)
class ParsedIdempotencyKey:
    key_hash: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class AuthenticatedIdempotencyScope:
    workspace_id: str
    principal: str


@dataclass(frozen=True, slots=True, repr=False)
class HttpIdempotencyRequest:
    fingerprint_input: RequestFingerprintInput = field(repr=False)
    raw_key_headers: tuple[str, ...] = field(repr=False)


@runtime_checkable
class IdempotentHttpMutationService(Protocol):
    def execute_idempotent(
        self,
        invocation: IdempotencyInvocation,
        mutation: IdempotencyMutation,
    ) -> PreSerializedHttpResponse: ...


def parse_idempotency_key(
    raw_values: Sequence[str] | None,
) -> ParsedIdempotencyKey | None:
    if raw_values is None:
        return None
    if len(raw_values) != 1:
        raise InvalidIdempotencyKey
    raw_key = raw_values[0]
    if not raw_key.isascii() or _KEY_PATTERN.fullmatch(raw_key) is None:
        raise InvalidIdempotencyKey
    return ParsedIdempotencyKey(hashlib.sha256(raw_key.encode("ascii")).digest())


def encode_json_response(
    response: V1HttpResponse,
) -> PreSerializedHttpResponse:
    payload = json.dumps(response.body, sort_keys=True).encode("utf-8")
    error_code: str | None = None
    decision: str | None = None
    raw_error = response.body.get("error")
    raw_decision = response.body.get("decision")
    error_code = raw_error if isinstance(raw_error, str) else None
    decision = raw_decision if isinstance(raw_decision, str) else None
    return PreSerializedHttpResponse(
        status_code=response.status_code,
        content_type=_CONTENT_TYPE,
        body=payload,
        observation=HttpResponseObservation(
            error_code=error_code,
            decision=decision,
        ),
    )


def cacheable_json_outcome(
    response: V1HttpResponse,
    replay_not_after_epoch: int | None = None,
) -> CacheableTerminalOutcome:
    return CacheableTerminalOutcome(
        response=encode_json_response(response),
        replay_not_after_epoch=replay_not_after_epoch,
    )


def invalid_key_response() -> PreSerializedHttpResponse:
    return _coarse_error("invalid_idempotency_key", 400)


def unavailable_response() -> PreSerializedHttpResponse:
    _LOGGER.error("idempotency_unavailable")
    return _coarse_error("idempotency_unavailable", 503)


def execute_idempotent_http(
    service: IdempotentHttpMutationService | None,
    request: HttpIdempotencyRequest,
    mutation: IdempotencyMutation,
) -> PreSerializedHttpResponse:
    try:
        request_fingerprint = idempotency_crypto.build_request_fingerprint(
            request.fingerprint_input
        )
    except IdempotencyFingerprintError:
        return unavailable_response()
    try:
        parsed_key = parse_idempotency_key(request.raw_key_headers)
    except InvalidIdempotencyKey:
        return invalid_key_response()
    assert parsed_key is not None
    if service is None:
        return unavailable_response()
    invocation = IdempotencyInvocation(
        workspace_id=request.fingerprint_input.authenticated_workspace_id,
        principal=request.fingerprint_input.authenticated_principal,
        operation=request.fingerprint_input.operation,
        key_hash=parsed_key.key_hash,
        request_fingerprint=request_fingerprint,
        max_terminal_ttl_seconds=_MAX_TERMINAL_TTL_SECONDS,
    )
    try:
        return service.execute_idempotent(invocation, mutation)
    except IdempotencyConflict:
        return _coarse_error("idempotency_key_conflict", 409)
    except (
        AmbiguousCommitError,
        IdempotencyCipherUnavailableError,
        IdempotencyResultUnavailable,
        IdempotencyWriteUnavailable,
    ):
        return unavailable_response()


def _coarse_error(code: str, status_code: int) -> PreSerializedHttpResponse:
    return encode_json_response(
        V1HttpResponse(
            status_code=status_code,
            body={"error": code, "reason": code},
        )
    )
