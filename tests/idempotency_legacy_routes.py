from __future__ import annotations

from datetime import timedelta

import pytest
from idempotency_http_fixtures import (
    AGENT_HEADERS,
    NOW,
    WORKSPACE_HEADERS,
    RawResponse,
    pending_request,
)
from idempotency_http_memory_transport import post_memory_json

import vinctor_core.audit
import vinctor_core.registry
import vinctor_service.auto_approval_http
import vinctor_service.grant_requests
import vinctor_service.grants
import vinctor_service.subject_tokens
from vinctor_core import Grant
from vinctor_service import InMemoryV1Service


def _deterministic_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    grant_counts: dict[str, int] = {}
    request_counts: dict[str, int] = {}
    grant_values = {
        ("grnt", 1): "grnt_pin_direct",
        ("grnt", 2): "grnt_pin_approve",
        ("grnt", 3): "grnt_pin_auto",
        ("grt", 1): "grt_pin_direct",
        ("evt", 1): "evt_pin_direct_grant",
        ("evt", 2): "evt_pin_approve_grant",
        ("evt", 3): "evt_pin_auto_grant",
    }
    request_values = {
        ("grt", 1): "grt_pin_approve",
        ("grt", 2): "grt_pin_auto",
        ("evt", 1): "evt_pin_approve_decision",
        ("evt", 2): "evt_pin_reject_decision",
        ("evt", 3): "evt_pin_auto_decision",
    }

    def next_grant_id(prefix: str) -> str:
        count = grant_counts.get(prefix, 0) + 1
        grant_counts[prefix] = count
        return grant_values[(prefix, count)]

    def next_request_id(prefix: str) -> str:
        count = request_counts.get(prefix, 0) + 1
        request_counts[prefix] = count
        return request_values[(prefix, count)]

    def fixed_subject_key(prefix: str, *, secret_bytes: int = 32) -> str:
        del secret_bytes
        return {"vat_": "vat_pin_legacy", "vtk_": "vtk_pin_legacy"}[prefix]

    monkeypatch.setattr(vinctor_service.grants, "_new_id", next_grant_id)
    monkeypatch.setattr(vinctor_service.grant_requests, "_new_id", next_request_id)
    monkeypatch.setattr(vinctor_service.subject_tokens, "_new_key", fixed_subject_key)
    monkeypatch.setattr(
        vinctor_service.subject_tokens,
        "token_urlsafe",
        lambda _size: "pin_token_audit",
    )
    monkeypatch.setattr(vinctor_core.registry, "_new_boundary_id", lambda: "bnd_pin_legacy")
    monkeypatch.setattr(
        vinctor_service.auto_approval_http,
        "_new_id",
        lambda _prefix: "apr_pin_legacy",
    )
    monkeypatch.setattr(vinctor_core.audit, "_new_event_id", lambda: "evt_pin_control")


def legacy_route_responses(monkeypatch: pytest.MonkeyPatch) -> tuple[RawResponse, ...]:
    _deterministic_ids(monkeypatch)
    service = InMemoryV1Service(
        grants=(
            Grant(
                grant_id="grnt_seed",
                grant_ref="grt_seed",
                workspace_id="ws_main",
                agent_id="agent_release",
                scopes=("write:repo/feature/*",),
                status="active",
                expires_at=NOW + timedelta(hours=1),
            ),
        )
    )
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )
    for request_id in ("grq_approve", "grq_reject", "grq_auto"):
        service.grant_request_repository.insert_request(
            pending_request(request_id, scopes=("write:repo/feature/readme",))
        )

    return (
        post_memory_json(
            service,
            "/v1/grants",
            {
                "agent_id": "agent_release",
                "scopes": ["write:repo/feature/readme"],
                "ttl_seconds": 60,
            },
            WORKSPACE_HEADERS,
        ),
        post_memory_json(
            service,
            "/v1/tokens",
            {"grant_ref": "grt_seed", "audience": "pep_main", "ttl_seconds": 60},
            AGENT_HEADERS,
        ),
        post_memory_json(
            service,
            "/v1/boundaries",
            {
                "name": "pin-boundary",
                "runtime": "codex",
                "boundary_type": "pretooluse",
                "mode": "fail_closed",
            },
            WORKSPACE_HEADERS,
        ),
        post_memory_json(
            service,
            "/v1/auto-approval-rules",
            {
                "name": "pin-rule",
                "target_agent_id": "agent_release",
                "allowed_scopes": ["write:repo/feature/*"],
                "max_ttl_seconds": 3600,
            },
            WORKSPACE_HEADERS,
        ),
        post_memory_json(
            service,
            "/v1/grant-requests/grq_approve/approve",
            {},
            WORKSPACE_HEADERS,
        ),
        post_memory_json(
            service,
            "/v1/grant-requests/grq_reject/reject",
            {},
            WORKSPACE_HEADERS,
        ),
        post_memory_json(
            service,
            "/v1/grant-requests/grq_auto/auto-approve",
            None,
            WORKSPACE_HEADERS,
        ),
    )
