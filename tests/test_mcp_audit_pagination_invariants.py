from __future__ import annotations

from typing import Any

import pytest

from vinctor_mcp_server.tools import VinctorReadOnlyTools, _AuditPaginationError


def _event(event_id: str) -> dict[str, Any]:
    sequence_text = event_id.removeprefix("evt_")
    return {
        "event_id": event_id,
        "event_type": "action_permitted",
        "event_class": "decision",
        "decision": "permit",
        "workspace_id": "ws_main",
        "agent_id": "agent_release",
        "grant_id": "grnt_main",
        "grant_ref": "grt_main",
        "boundary_id": "bnd_main",
        "created_at": "2026-06-11T12:00:00+00:00",
        "sequence": int(sequence_text) if sequence_text.isdigit() else 1,
    }


class _ScriptedReportClient:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self._pages = iter(pages)

    def get_grant(self, grant_ref: str) -> dict[str, Any]:
        return {
            "grant_id": "grnt_main",
            "grant_ref": grant_ref,
            "workspace_id": "ws_main",
            "agent_id": "agent_release",
            "status": "active",
            "expires_at": None,
        }

    def list_audit_events(self, **_filters: Any) -> dict[str, Any]:
        return next(self._pages)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(
            {
                "page": {
                    "snapshot_event_id": None,
                    "next_before_event_id": None,
                }
            },
            id="missing-audit-events",
        ),
        pytest.param(
            {
                "audit_events": {"payload": "sensitive-page-detail"},
                "page": {
                    "snapshot_event_id": None,
                    "next_before_event_id": None,
                },
            },
            id="non-list-audit-events",
        ),
        pytest.param(
            {
                "audit_events": [_event("evt_001"), "sensitive-page-detail"],
                "page": {
                    "snapshot_event_id": "evt_001",
                    "next_before_event_id": None,
                },
            },
            id="mixed-audit-events",
        ),
        pytest.param(
            {
                "audit_events": [{"event_type": "action_permitted"}],
                "page": {
                    "snapshot_event_id": "evt_001",
                    "next_before_event_id": None,
                },
            },
            id="missing-event-id",
        ),
        pytest.param(
            {
                "audit_events": [_event("")],
                "page": {
                    "snapshot_event_id": "evt_001",
                    "next_before_event_id": None,
                },
            },
            id="empty-event-id",
        ),
        pytest.param(
            {
                "audit_events": [{**_event("evt_001"), "event_id": 1}],
                "page": {
                    "snapshot_event_id": "evt_001",
                    "next_before_event_id": None,
                },
            },
            id="non-string-event-id",
        ),
        pytest.param(
            {"audit_events": []},
            id="missing-page",
        ),
        pytest.param(
            {
                "audit_events": [],
                "page": "sensitive-page-detail",
            },
            id="non-dict-page",
        ),
        pytest.param(
            {
                "audit_events": [_event("evt_001")],
                "page": {
                    "snapshot_event_id": ["sensitive-page-detail"],
                    "next_before_event_id": None,
                },
            },
            id="non-string-snapshot",
        ),
        pytest.param(
            {
                "audit_events": [_event("evt_001")],
                "page": {
                    "snapshot_event_id": "evt_001",
                    "next_before_event_id": ["sensitive-page-detail"],
                },
            },
            id="non-string-before",
        ),
    ],
)
def test_report_paging_rejects_malformed_service_payload(
    body: dict[str, Any],
) -> None:
    # Given: a malformed service page containing data that must not be disclosed.
    client = _ScriptedReportClient([body])

    # When: report composition consumes the malformed response.
    with pytest.raises(_AuditPaginationError) as raised:
        VinctorReadOnlyTools(client).grant_report("grt_main")

    # Then: composition fails coarsely without echoing service payload details.
    assert "sensitive-page-detail" not in str(raised.value)


def test_report_paging_rejects_changed_snapshot_echo() -> None:
    # Given: a continuation response that changes the first page's snapshot.
    client = _ScriptedReportClient(
        [
            {
                "audit_events": [_event("evt_002")],
                "page": {
                    "snapshot_event_id": "evt_002",
                    "next_before_event_id": "evt_002",
                },
            },
            {
                "audit_events": [_event("evt_001")],
                "page": {
                    "snapshot_event_id": "evt_changed",
                    "next_before_event_id": None,
                },
            },
        ]
    )

    # When/Then: report composition rejects the inconsistent snapshot.
    with pytest.raises(_AuditPaginationError):
        VinctorReadOnlyTools(client).grant_report("grt_main")


def test_report_paging_rejects_empty_continuation_page() -> None:
    # Given: a non-terminal first page followed by an empty continuation.
    client = _ScriptedReportClient(
        [
            {
                "audit_events": [_event("evt_002")],
                "page": {
                    "snapshot_event_id": "evt_002",
                    "next_before_event_id": "evt_002",
                },
            },
            {
                "audit_events": [],
                "page": {
                    "snapshot_event_id": "evt_002",
                    "next_before_event_id": None,
                },
            },
        ]
    )

    # When/Then: report composition fails instead of returning a partial report.
    with pytest.raises(_AuditPaginationError):
        VinctorReadOnlyTools(client).grant_report("grt_main")


def test_report_paging_rejects_duplicate_event_id() -> None:
    # Given: the same audit event appears in two page windows.
    client = _ScriptedReportClient(
        [
            {
                "audit_events": [_event("evt_002")],
                "page": {
                    "snapshot_event_id": "evt_002",
                    "next_before_event_id": "evt_002",
                },
            },
            {
                "audit_events": [_event("evt_002")],
                "page": {
                    "snapshot_event_id": "evt_002",
                    "next_before_event_id": None,
                },
            },
        ]
    )

    # When/Then: report composition rejects duplicate counting.
    with pytest.raises(_AuditPaginationError):
        VinctorReadOnlyTools(client).grant_report("grt_main")


def test_report_paging_rejects_cursor_outside_current_page() -> None:
    # Given: a service cursor that does not identify the current page's oldest event.
    client = _ScriptedReportClient(
        [
            {
                "audit_events": [_event("evt_002")],
                "page": {
                    "snapshot_event_id": "evt_002",
                    "next_before_event_id": "evt_missing",
                },
            },
            {
                "audit_events": [_event("evt_001")],
                "page": {
                    "snapshot_event_id": "evt_002",
                    "next_before_event_id": None,
                },
            },
        ]
    )

    # When/Then: report composition rejects the non-progressing cursor.
    with pytest.raises(_AuditPaginationError):
        VinctorReadOnlyTools(client).grant_report("grt_main")


def test_report_paging_rejects_repeated_cursor() -> None:
    # Given: a continuation repeats the cursor already used to reach it.
    client = _ScriptedReportClient(
        [
            {
                "audit_events": [_event("evt_002")],
                "page": {
                    "snapshot_event_id": "evt_002",
                    "next_before_event_id": "evt_002",
                },
            },
            {
                "audit_events": [_event("evt_001")],
                "page": {
                    "snapshot_event_id": "evt_002",
                    "next_before_event_id": "evt_002",
                },
            },
        ]
    )

    # When/Then: report composition rejects the non-advancing loop.
    with pytest.raises(_AuditPaginationError):
        VinctorReadOnlyTools(client).grant_report("grt_main")
