from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from vinctor_core.models import AuditEvent
from vinctor_service.audit_http import handle_v1_audit_events_http
from vinctor_service.boundary_http import WorkspaceIdentity
from vinctor_service.in_memory import InMemoryV1Service
from vinctor_service.v1_http import V1HttpResponse

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)


def _event(
    index: int,
    *,
    workspace_id: str = "ws_main",
    grant_ref: str = "grt_main",
) -> AuditEvent:
    return AuditEvent(
        event_id=f"evt_{index:03d}",
        event_type="action_permitted",
        decision="permit",
        reason="action_permitted",
        workspace_id=workspace_id,
        agent_id="agent_release",
        grant_id="grnt_main",
        grant_ref=grant_ref,
        action="send",
        resource="email/external",
        scope_attempted="send:email/external",
        scope_matched="send:email/*",
        boundary_id="bnd_main",
        runtime="codex",
        boundary_type="pretooluse",
        created_at=NOW + timedelta(seconds=index),
    )


def _list_page(
    service: InMemoryV1Service,
    query_string: str,
) -> V1HttpResponse:
    return handle_v1_audit_events_http(
        method="GET",
        path="/v1/audit-events",
        query_string=query_string,
        headers={"X-Workspace-Key": "wsk_main"},
        workspace_identities={
            "wsk_main": WorkspaceIdentity(workspace_id="ws_main")
        },
        service=service,
        now=NOW,
    )


def test_audit_pages_keep_a_stable_snapshot_while_the_tail_grows() -> None:
    service = InMemoryV1Service()
    for index in range(205):
        service.audit_writer.write(_event(index))
    service.audit_writer.write(_event(900, workspace_id="ws_other"))
    service.audit_writer.write(_event(901, grant_ref="grt_other"))

    first = _list_page(service, "page=true&limit=100&grant_ref=grt_main")
    first_page = first.body["page"]
    service.audit_writer.write(replace(_event(999), event_id="evt_concurrent"))
    second = _list_page(
        service,
        "page=true&limit=100&grant_ref=grt_main"
        f"&snapshot_event_id={first_page['snapshot_event_id']}"
        f"&before_event_id={first_page['next_before_event_id']}",
    )
    second_page = second.body["page"]
    third = _list_page(
        service,
        "page=true&limit=100&grant_ref=grt_main"
        f"&snapshot_event_id={second_page['snapshot_event_id']}"
        f"&before_event_id={second_page['next_before_event_id']}",
    )

    event_ids = [
        event["event_id"]
        for response in (third, second, first)
        for event in response.body["audit_events"]
    ]
    assert event_ids == [f"evt_{index:03d}" for index in range(205)]
    assert first_page == {
        "snapshot_event_id": "evt_204",
        "next_before_event_id": "evt_105",
    }
    assert third.body["page"]["next_before_event_id"] is None


def test_default_audit_list_keeps_the_newest_twenty_shape() -> None:
    service = InMemoryV1Service()
    for index in range(25):
        service.audit_writer.write(_event(index))

    response = _list_page(service, "grant_ref=grt_main")

    assert list(response.body) == ["audit_events"]
    assert [event["event_id"] for event in response.body["audit_events"]] == [
        f"evt_{index:03d}" for index in range(5, 25)
    ]
    assert all("sequence" not in event for event in response.body["audit_events"])


def test_paginated_audit_list_exposes_chain_sequence() -> None:
    # Given: three chain events with the same application timestamp.
    service = InMemoryV1Service()
    for index in range(3):
        service.audit_writer.write(replace(_event(index), created_at=NOW))

    # When: the operator requests the paginated audit contract used by MCP reports.
    response = _list_page(service, "page=true&limit=100&grant_ref=grt_main")

    # Then: each event carries its tamper-evident global chain position.
    assert [event["sequence"] for event in response.body["audit_events"]] == [1, 2, 3]


@pytest.mark.parametrize(
    "query_string",
    [
        "page=true&snapshot_event_id=evt_unknown",
        "page=true&snapshot_event_id=evt_900",
        "page=true&before_event_id=evt_001",
        "page=true&snapshot_event_id=evt_001&before_event_id=evt_unknown",
        "page=true&snapshot_event_id=evt_001&before_event_id=evt_900",
        "page=true&snapshot_event_id=evt_001&before_event_id=evt_002",
    ],
)
def test_audit_page_rejects_invalid_cursor_without_disclosure(
    query_string: str,
) -> None:
    # Given: authenticated same-workspace cursors and one cross-workspace cursor.
    service = InMemoryV1Service()
    service.audit_writer.write(_event(1))
    service.audit_writer.write(_event(2))
    service.audit_writer.write(_event(900, workspace_id="ws_other"))

    # When: a caller supplies an invalid cursor or inverted cursor pair.
    response = _list_page(service, query_string)

    # Then: every class receives one coarse response with no existence detail.
    assert response.status_code == 400
    assert response.body == {
        "error": "invalid_request",
        "reason": "invalid cursor",
    }


@pytest.mark.parametrize(
    "query_string",
    [
        "page=false",
        "snapshot_event_id=evt_001",
        "page=true&before_event_id=evt_001",
        "page=true&limit=101",
    ],
)
def test_audit_page_rejects_invalid_boundary_inputs(query_string: str) -> None:
    response = _list_page(InMemoryV1Service(), query_string)

    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"
