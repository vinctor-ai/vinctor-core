from __future__ import annotations

from collections.abc import Iterator

import pytest

from vinctor_mcp_server.tools import VinctorReadOnlyTools, _AuditPaginationError


def _event(event_id: str, **overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "event_id": event_id,
        "event_type": "action_permitted",
        "event_class": "decision",
        "decision": "permit",
        "reason": "allowed",
        "workspace_id": "ws_main",
        "agent_id": "agent_release",
        "grant_id": "grnt_main",
        "grant_ref": "grt_main",
        "action": "send",
        "resource": "email/external",
        "boundary_id": "bnd_main",
        "runtime": "codex",
        "boundary_type": "pretooluse",
        "created_at": "2026-07-19T12:00:00+00:00",
        "sequence": 1,
        "subject_token_verified": True,
    }
    event.update(overrides)
    return event


def _page(
    events: list[dict[str, object]],
    *,
    snapshot_event_id: object,
    next_before_event_id: object,
) -> dict[str, object]:
    return {
        "audit_events": events,
        "page": {
            "snapshot_event_id": snapshot_event_id,
            "next_before_event_id": next_before_event_id,
        },
    }


class _ScriptedClient:
    def __init__(self, pages: list[dict[str, object]]) -> None:
        self._pages: Iterator[dict[str, object]] = iter(pages)

    def get_grant(self, grant_ref: str) -> dict[str, object]:
        return {
            "grant_id": "grnt_main",
            "grant_ref": grant_ref,
            "workspace_id": "ws_main",
            "agent_id": "agent_release",
            "status": "active",
            "expires_at": None,
        }

    def list_audit_events(self, **_filters: object) -> dict[str, object]:
        return next(self._pages)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(
            _page(
                [],
                snapshot_event_id="evt_hidden",
                next_before_event_id=None,
            ),
            id="empty-events-with-snapshot",
        ),
        pytest.param(
            {
                "audit_events": [_event("evt_001")],
                "page": {"snapshot_event_id": "evt_001"},
            },
            id="missing-next-cursor-key",
        ),
        pytest.param(
            {
                "audit_events": [_event("evt_001")],
                "page": {"next_before_event_id": None},
            },
            id="missing-snapshot-key",
        ),
        pytest.param(
            _page(
                [_event("evt_001")],
                snapshot_event_id="evt_other",
                next_before_event_id=None,
            ),
            id="first-snapshot-not-newest-event",
        ),
    ],
)
def test_report_rejects_incoherent_first_audit_page(
    body: dict[str, object],
) -> None:
    # Given: a first page whose metadata cannot describe its returned events.
    tools = VinctorReadOnlyTools(_ScriptedClient([body]))

    # When/Then: report composition fails rather than accepting a partial history.
    with pytest.raises(_AuditPaginationError):
        tools.grant_report("grt_main")


@pytest.mark.parametrize(
    ("field", "malformed"),
    [
        pytest.param("event_type", "", id="event-type"),
        pytest.param("event_class", "sensitive-page-detail", id="event-class"),
        pytest.param(
            "decision",
            {"payload": "sensitive-page-detail"},
            id="decision",
        ),
        pytest.param("workspace_id", None, id="workspace-id"),
        pytest.param("agent_id", ["sensitive-page-detail"], id="agent-id"),
        pytest.param("grant_id", 7, id="grant-id"),
        pytest.param(
            "grant_ref",
            {"payload": "sensitive-page-detail"},
            id="grant-ref",
        ),
        pytest.param("boundary_id", ["sensitive-page-detail"], id="boundary-id"),
        pytest.param("created_at", "sensitive-page-detail", id="created-at"),
        pytest.param("sequence", "sensitive-page-detail", id="sequence"),
    ],
)
def test_report_rejects_malformed_audit_fields_without_echo(
    field: str,
    malformed: object,
) -> None:
    # Given: a page with one malformed field used by report logic.
    event = _event("evt_001")
    event[field] = malformed
    body = _page(
        [event],
        snapshot_event_id="evt_001",
        next_before_event_id=None,
    )

    # When: report composition parses the service response.
    with pytest.raises(_AuditPaginationError) as raised:
        VinctorReadOnlyTools(_ScriptedClient([body])).grant_report("grt_main")

    # Then: the failure is coarse and never echoes the malformed payload.
    assert "sensitive-page-detail" not in str(raised.value)


def test_report_accepts_empty_history_without_snapshot() -> None:
    # Given: the canonical representation of a valid no-event history.
    body = _page([], snapshot_event_id=None, next_before_event_id=None)

    # When: a grant report consumes the page.
    report = VinctorReadOnlyTools(_ScriptedClient([body])).grant_report("grt_main")

    # Then: it reports no events without fabricating a snapshot.
    assert report["lifecycle"] == []
    assert report["usage"] == []


class _OverlappingGrantRequestClient:
    def get_grant_request(self, request_id: str) -> dict[str, object]:
        return {
            "request_id": request_id,
            "issued_grant_ref": "grt_issued",
            "status": "approved",
        }

    def get_grant(self, grant_ref: str) -> dict[str, object]:
        return {
            "grant_id": "grnt_issued",
            "grant_ref": grant_ref,
            "workspace_id": "ws_main",
            "agent_id": "agent_release",
            "status": "active",
            "expires_at": None,
        }

    def list_audit_events(self, **filters: object) -> dict[str, object]:
        requested = _event(
            "evt_requested",
            event_type="grant_requested",
            event_class="control",
            grant_id="grq_main",
            grant_ref="grq_main",
            sequence=1,
        )
        issued = _event(
            "evt_issued",
            event_type="grant_issued",
            event_class="control",
            grant_id="grnt_issued",
            grant_ref="grt_issued",
            sequence=2,
        )
        approved = _event(
            "evt_approved",
            event_type="grant_request_approved",
            event_class="control",
            grant_id="grnt_issued",
            grant_ref="grt_issued",
            sequence=3,
        )
        events = (
            [requested, approved]
            if filters.get("request_id") == "grq_main"
            else [issued, approved]
        )
        return _page(
            events,
            snapshot_event_id=events[-1]["event_id"],
            next_before_event_id=None,
        )


def test_grant_request_report_merges_overlap_in_audit_chain_order() -> None:
    # Given: request and grant views overlap at approval but expose different edges.
    tools = VinctorReadOnlyTools(_OverlappingGrantRequestClient())

    # When: the report merges both complete streams.
    report = tools.grant_request_report("grq_main")

    # Then: deduplication preserves the global write chronology.
    assert [event["event_id"] for event in report["timeline"]] == [
        "evt_requested",
        "evt_issued",
        "evt_approved",
    ]
    assert [event["sequence"] for event in report["timeline"]] == [1, 2, 3]
