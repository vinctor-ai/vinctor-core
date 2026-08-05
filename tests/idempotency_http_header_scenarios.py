from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from idempotency_http_fixtures import (
    NOW,
    RawResponse,
)
from idempotency_http_memory_transport import post_memory_raw_json

from vinctor_service import InMemoryV1Service
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import connect_sqlite

VALID_GRANT_BODY = (
    b'{"agent_id":"agent_release","scopes":["write:repo/feature/readme"],"ttl_seconds":60}'
)


@dataclass(frozen=True, slots=True)
class HeaderOutcome:
    response: RawResponse
    grant_count: int
    audit_count: int


@dataclass(frozen=True, slots=True)
class PrecedenceOutcome:
    responses: tuple[RawResponse, RawResponse, RawResponse]
    grant_count: int
    audit_count: int


@dataclass(frozen=True, slots=True)
class RawKeyOutcome:
    response: RawResponse
    database_dump: str
    audit_text: str
    database_bytes: bytes


def mutable_service() -> InMemoryV1Service:
    service = InMemoryV1Service()
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )
    return service


def exercise_header_lines(values: tuple[str, ...]) -> HeaderOutcome:
    service = mutable_service()
    raw_headers = (
        ("X-Workspace-Key", "workspace_key_main"),
        *(("Idempotency-Key", value) for value in values),
    )
    response = post_memory_raw_json(
        service,
        "/v1/grants",
        VALID_GRANT_BODY,
        raw_headers,
    )
    return HeaderOutcome(
        response=response,
        grant_count=len(service.list_grants(workspace_id="ws_main")),
        audit_count=len(service.audit_events),
    )


def exercise_validation_precedence() -> PrecedenceOutcome:
    service = mutable_service()
    unauthenticated = post_memory_raw_json(
        service,
        "/v1/grants",
        VALID_GRANT_BODY,
        (("Idempotency-Key", "bad key"),),
    )
    malformed = post_memory_raw_json(
        service,
        "/v1/grants",
        b"{",
        (
            ("X-Workspace-Key", "workspace_key_main"),
            ("Idempotency-Key", "bad key"),
        ),
    )
    invalid_key = post_memory_raw_json(
        service,
        "/v1/grants",
        VALID_GRANT_BODY,
        (
            ("X-Workspace-Key", "workspace_key_main"),
            ("Idempotency-Key", "bad key"),
        ),
    )
    return PrecedenceOutcome(
        responses=(unauthenticated, malformed, invalid_key),
        grant_count=len(service.list_grants(workspace_id="ws_main")),
        audit_count=len(service.audit_events),
    )


def exercise_raw_key_redaction(database: Path, raw_key: str) -> RawKeyOutcome:
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(connection)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )
    try:
        response = post_memory_raw_json(
            service,
            "/v1/grants",
            VALID_GRANT_BODY,
            (
                ("X-Workspace-Key", "workspace_key_main"),
                ("Idempotency-Key", raw_key),
            ),
        )
        database_dump = "\n".join(connection.iterdump())
        audit_text = repr(service.audit_events)
    finally:
        connection.close()
    return RawKeyOutcome(
        response=response,
        database_dump=database_dump,
        audit_text=audit_text,
        database_bytes=database.read_bytes(),
    )


def exercise_absent_keyring() -> HeaderOutcome:
    service = mutable_service()
    response = post_memory_raw_json(
        service,
        "/v1/grants",
        VALID_GRANT_BODY,
        (
            ("X-Workspace-Key", "workspace_key_main"),
            ("Idempotency-Key", "requires-keyring"),
        ),
    )
    return HeaderOutcome(
        response=response,
        grant_count=len(service.list_grants(workspace_id="ws_main")),
        audit_count=len(service.audit_events),
    )
