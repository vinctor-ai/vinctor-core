from __future__ import annotations

from datetime import timedelta

import pytest
from idempotency_http_fixtures import (
    AGENTS,
    NOW,
    WORKSPACE_HEADERS,
    WORKSPACES,
    pending_request,
)
from idempotency_legacy_routes import legacy_route_responses
from idempotency_legacy_wire import EXPECTED_LEGACY_RESPONSES

from vinctor_core import Grant
from vinctor_service import (
    AutoApprovalRule,
    InMemoryV1Service,
)
from vinctor_service.grant_http import handle_v1_grants_http
from vinctor_service.grant_request_http import handle_v1_grant_requests_http
from vinctor_service.v1_http import handle_v1_tokens_http

AGENT_HEADERS = {"X-Agent-Key": "agent_key_main"}


def _decision(service: InMemoryV1Service, request_id: str, action: str):
    return handle_v1_grant_requests_http(
        method="POST",
        path=f"/v1/grant-requests/{request_id}/{action}",
        headers=WORKSPACE_HEADERS,
        body=None,
        workspace_identities=WORKSPACES,
        service=service,
        now=NOW + timedelta(seconds=1),
    )


def test_unkeyed_seven_route_status_content_type_and_body_bytes_are_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given deterministic legacy IDs and seven requests without Idempotency-Key.
    expected = EXPECTED_LEGACY_RESPONSES

    # When all protected mutations traverse the real HTTP serializer.
    responses = legacy_route_responses(monkeypatch)

    # Then every complete wire tuple equals an independent fixed legacy value.
    actual = tuple(
        (
            response.status_code,
            response.content_type,
            response.content_length,
            response.body,
        )
        for response in responses
    )
    assert actual == expected


def test_grant_service_semantic_400_calls_no_audit() -> None:
    # Given a transport-valid grant request with a service-invalid scope.
    service = InMemoryV1Service()

    # When the grant service rejects the semantic input.
    response = handle_v1_grants_http(
        method="POST",
        path="/v1/grants",
        headers=WORKSPACE_HEADERS,
        body={"agent_id": "agent_release", "scopes": ["not-a-scope"], "ttl_seconds": 60},
        workspace_identities=WORKSPACES,
        service=service,
        now=NOW,
    )

    # Then the deterministic 400 remains unaudited.
    assert response.status_code == 400
    assert response.body == {
        "error": "invalid_requested_scope",
        "reason": "invalid_requested_scope",
    }
    assert service.audit_events == ()


@pytest.mark.parametrize(
    ("bounds", "max_ttl", "expected_reason"),
    [
        (None, None, "issuable_bounds_not_found"),
        (("read:repo/feature/*",), None, "scope_outside_issuable_bounds"),
        (("write:repo/feature/*",), 30, "ttl_exceeds_issuable_max"),
    ],
)
def test_grant_bounds_403_is_best_effort(
    bounds: tuple[str, ...] | None,
    max_ttl: int | None,
    expected_reason: str,
) -> None:
    # Given one of the three attributable issuance-bound failures.
    service = InMemoryV1Service()
    if bounds is not None:
        service.set_agent_issuable_scope_bounds(
            workspace_id="ws_main",
            agent_id="agent_release",
            scopes=bounds,
            max_ttl_seconds=max_ttl,
            now=NOW,
        )

    # When a workspace requests the grant.
    response = handle_v1_grants_http(
        method="POST",
        path="/v1/grants",
        headers=WORKSPACE_HEADERS,
        body={
            "agent_id": "agent_release",
            "scopes": ["write:repo/feature/readme"],
            "ttl_seconds": 60,
        },
        workspace_identities=WORKSPACES,
        service=service,
        now=NOW,
    )

    # Then the 403 and its single best-effort rejection audit remain distinct.
    assert response.status_code == 403
    assert response.body["reason"] == expected_reason
    assert len(service.audit_events) == 1
    assert service.audit_events[0].reason == expected_reason


def test_approve_issue_400_restores_pending_without_audit() -> None:
    # Given a legacy pending row whose nested grant issue is semantically invalid.
    service = InMemoryV1Service()
    service.grant_request_repository.insert_request(
        pending_request("grq_invalid", scopes=("not-a-scope",))
    )

    # When the workspace attempts approval.
    response = _decision(service, "grq_invalid", "approve")

    # Then the claim is restored, the 400 is stable, and no audit was written.
    assert response.status_code == 400
    assert response.body["reason"] == "invalid_requested_scope"
    assert (
        service.lookup_grant_request(request_id="grq_invalid", workspace_id="ws_main").status
        == "pending"
    )
    assert service.audit_events == ()


def test_approve_bounds_403_restores_pending_with_best_effort_audit() -> None:
    # Given a pending request outside the configured issuance bounds.
    service = InMemoryV1Service()
    service.grant_request_repository.insert_request(
        pending_request("grq_bounds", scopes=("execute:deploy/env/production",))
    )
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )

    # When the workspace attempts approval.
    response = _decision(service, "grq_bounds", "approve")

    # Then the 403 restores pending and writes only the attributable rejection.
    assert response.status_code == 403
    assert response.body["reason"] == "scope_outside_issuable_bounds"
    assert (
        service.lookup_grant_request(request_id="grq_bounds", workspace_id="ws_main").status
        == "pending"
    )
    assert [event.reason for event in service.audit_events] == ["scope_outside_issuable_bounds"]


def test_auto_approve_nested_issue_status_and_audit_match_approve() -> None:
    # Given an auto-approval rule that matches a request outside issuance bounds.
    service = InMemoryV1Service()
    service.grant_request_repository.insert_request(
        pending_request("grq_auto_bounds", scopes=("execute:deploy/env/production",))
    )
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )
    service.create_auto_approval_rule(
        AutoApprovalRule(
            rule_id="apr_pin",
            workspace_id="ws_main",
            name="pin auto approval",
            target_agent_id="agent_release",
            allowed_scopes=("execute:deploy/env/*",),
            max_ttl_seconds=3600,
            status="active",
            created_by="workspace:ws_main",
            created_at=NOW,
        )
    )

    # When auto-approval reaches the nested grant issue.
    response = _decision(service, "grq_auto_bounds", "auto-approve")

    # Then it matches manual approval's 403, pending restoration, and one audit.
    assert response.status_code == 403
    assert response.body["reason"] == "scope_outside_issuable_bounds"
    assert (
        service.lookup_grant_request(request_id="grq_auto_bounds", workspace_id="ws_main").status
        == "pending"
    )
    assert [event.reason for event in service.audit_events] == ["scope_outside_issuable_bounds"]


def test_token_403_is_generic_and_best_effort() -> None:
    # Given an authenticated agent probing a grant owned by another agent.
    service = InMemoryV1Service(
        grants=(
            Grant(
                grant_id="grnt_foreign",
                grant_ref="grt_foreign",
                workspace_id="ws_main",
                agent_id="agent_other",
                scopes=("write:repo/feature/*",),
                status="active",
                expires_at=NOW + timedelta(hours=1),
            ),
        )
    )

    # When the agent requests a subject token.
    response = handle_v1_tokens_http(
        headers=AGENT_HEADERS,
        body={"grant_ref": "grt_foreign", "audience": "pep_main", "ttl_seconds": 60},
        agent_identities=AGENTS,
        service=service,
        now=NOW,
    )

    # Then the caller sees one generic 403 while the operator gets one coarse audit.
    assert response.status_code == 403
    assert response.body == {
        "error": "forbidden",
        "reason": "subject token could not be issued",
    }
    assert len(service.audit_events) == 1
    event = service.audit_events[0]
    assert event.reason == "agent_grant_mismatch"
    assert event.grant_ref == ""
