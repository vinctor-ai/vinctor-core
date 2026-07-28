from datetime import UTC, datetime

from vinctor_service.audit_http import handle_v1_service_auth_failures_http
from vinctor_service.keys import SERVICE_OPERATOR_KEY_PREFIX, SQLiteLocalKeyRepository
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)


def test_service_operator_key_is_global_and_not_a_workspace_identity() -> None:
    service = SQLiteV1Service(connect_sqlite(":memory:"))
    repository = SQLiteLocalKeyRepository(service.conn)
    created = repository.create_service_operator_key(
        raw_key="sok_test_secret",
        now=NOW,
    )

    assert created.raw_key.startswith(SERVICE_OPERATOR_KEY_PREFIX)
    assert created.record.key_type == "service_operator"
    assert repository.resolve_service_operator("sok_test_secret", now=NOW)
    assert repository.resolve_workspace_identity("sok_test_secret", now=NOW) is None
    assert repository.resolve_auditor_identity("sok_test_secret", now=NOW) is None


def test_service_operator_view_returns_only_unscoped_auth_failures() -> None:
    service = SQLiteV1Service(connect_sqlite(":memory:"))
    service.record_auth_failure(surface="enforce", now=NOW)

    response = handle_v1_service_auth_failures_http(
        method="GET",
        path="/v1/service/audit/auth-failures",
        query_string="limit=10",
        headers={"X-Service-Operator-Key": "sok_main"},
        service_operator_keys={"sok_main"},
        service=service,
        now=NOW,
    )

    assert response.status_code == 200
    assert [event["event_type"] for event in response.body["auth_failures"]] == [
        "auth_failed"
    ]
    assert response.body["auth_failures"][0]["workspace_id"] == ""


def test_workspace_key_cannot_read_global_auth_failures() -> None:
    service = SQLiteV1Service(connect_sqlite(":memory:"))
    service.record_auth_failure(surface="enforce", now=NOW)

    response = handle_v1_service_auth_failures_http(
        method="GET",
        path="/v1/service/audit/auth-failures",
        query_string="",
        headers={"X-Workspace-Key": "wsk_main"},
        service_operator_keys=set(),
        service=service,
        now=NOW,
    )

    assert response.status_code == 401
    assert response.body["error"] == "authentication_required"
