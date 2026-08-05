from __future__ import annotations

from dataclasses import dataclass

from idempotency_http_fixtures import JsonMutationPayload


@dataclass(frozen=True, slots=True)
class RouteCase:
    label: str
    operation: str
    path: str
    payload: JsonMutationPayload
    headers: dict[str, str]
    status_code: int
    state_field: str
    state_delta: int
    audit_delta: int
