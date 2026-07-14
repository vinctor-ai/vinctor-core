import sqlite3
from datetime import UTC, datetime

from vinctor_service.audit_http import handle_v1_audit_events_http
from vinctor_service.boundary_http import WorkspaceIdentity
from vinctor_service.keys import AUDITOR_KEY_PREFIX, SQLiteLocalKeyRepository
from vinctor_service.sqlite import SQLiteV1Service

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)


class _AuditService:
    def __init__(self) -> None:
        self.requested_workspace_id: str | None = None

    def list_filtered(self, workspace_id: str, **filters):
        self.requested_workspace_id = workspace_id
        return ()

    def get_audit_event(self, event_id: str):
        return None


def test_auditor_key_is_workspace_scoped_and_cannot_resolve_as_operator() -> None:
    service = SQLiteV1Service(sqlite3.connect(":memory:"))
    repository = SQLiteLocalKeyRepository(service.conn)
    created = repository.create_auditor_key(
        workspace_id="ws_main",
        raw_key="auk_test_secret",
        now=NOW,
    )

    identity = repository.resolve_auditor_identity("auk_test_secret", now=NOW)
    assert created.raw_key.startswith(AUDITOR_KEY_PREFIX)
    assert created.record.key_type == "auditor"
    assert identity == WorkspaceIdentity(workspace_id="ws_main")
    assert repository.resolve_workspace_identity("auk_test_secret", now=NOW) is None


def test_auditor_header_can_read_only_its_workspace_audit() -> None:
    service = _AuditService()
    response = handle_v1_audit_events_http(
        method="GET",
        path="/v1/audit-events",
        query_string="",
        headers={"X-Auditor-Key": "auk_main"},
        auditor_identities={"auk_main": WorkspaceIdentity(workspace_id="ws_main")},
        service=service,
        now=NOW,
    )

    assert response.status_code == 200
    assert response.body == {"audit_events": []}
    assert service.requested_workspace_id == "ws_main"


def test_workspace_auditor_cannot_read_unscoped_auth_failures() -> None:
    service = SQLiteV1Service(sqlite3.connect(":memory:"))
    service.record_auth_failure(surface="enforce", now=NOW)

    response = handle_v1_audit_events_http(
        method="GET",
        path="/v1/audit-events",
        query_string="event_type=auth_failed",
        headers={"X-Auditor-Key": "auk_main"},
        auditor_identities={"auk_main": WorkspaceIdentity(workspace_id="ws_main")},
        service=service,
        now=NOW,
    )

    assert response.status_code == 200
    assert response.body == {"audit_events": []}
