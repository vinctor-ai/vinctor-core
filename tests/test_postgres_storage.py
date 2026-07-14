from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from vinctor_core.models import AuditEvent, Grant
from vinctor_service.models import V1EnforceRequest, V1ObserveRequest
from vinctor_service.policy_infer import infer_policy_document
from vinctor_service.postgres import (
    PostgresAuditWriter,
    PostgresGrantRepository,
    PostgresV1Service,
    connect_postgres,
    init_postgres_schema,
)
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.storage_runtime import prepare_decision_storage

DSN = os.environ.get("VINCTOR_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="VINCTOR_TEST_POSTGRES_DSN is not set")
NOW = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def clean_database():
    assert DSN is not None
    conn = connect_postgres(DSN)
    init_postgres_schema(conn)
    with conn.transaction():
        conn.execute("TRUNCATE TABLE audit_events, grants")
    conn.close()


def grant() -> Grant:
    return Grant(
        grant_id="grnt_main",
        grant_ref="grt_main",
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


def test_postgres_grant_repository_lifecycle() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    repository = PostgresGrantRepository(conn)

    repository.insert(grant())

    assert repository.get_by_ref("grt_main") == grant()
    assert repository.list_grants_for_workspace("ws_main") == (grant(),)
    revoked = repository.revoke(grant_ref="grt_main", workspace_id="ws_main")
    assert revoked is not None
    assert revoked.status == "revoked"
    conn.close()


def test_postgres_runtime_selection_initializes_and_reports_ready() -> None:
    assert DSN is not None

    handle = prepare_decision_storage(
        ServiceRuntimeConfig(storage_backend="postgres", postgres_dsn=DSN)
    )
    try:
        assert handle.backend == "postgres"
        assert isinstance(handle.service, PostgresV1Service)
        assert handle.is_ready()
    finally:
        handle.close()


def test_postgres_service_enforces_and_persists_audit() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    service = PostgresV1Service(conn)
    service.insert_grant(grant())

    response = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            grant_ref="grt_main",
            action="write",
            resource="repo/feature/readme",
        ),
        now=NOW,
    )

    assert response.status_code == 200
    assert response.audit_event_id == service.audit_events[0].event_id
    assert service.audit_events[0].event_type == "action_permitted"
    conn.close()


def test_postgres_observation_feeds_exact_policy_proposal() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    service = PostgresV1Service(conn)

    response = service.observe(
        V1ObserveRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            classification="mapped",
            action="read",
            resource="repo/feature/readme",
        ),
        now=NOW,
    )
    proposal = infer_policy_document(service.audit_events, agent_id="agent_release")

    assert response.status_code == 200
    assert proposal["proposed"]["scopes"] == [
        {
            "scope": "read:repo/feature/readme",
            "count": 1,
            "last_seen": NOW.isoformat(),
        }
    ]
    conn.close()


def test_postgres_audit_chain_serializes_multiple_instances() -> None:
    assert DSN is not None

    def write(index: int) -> None:
        conn = connect_postgres(DSN)
        writer = PostgresAuditWriter(conn)
        writer.write(
            AuditEvent(
                event_id=f"evt_{index}",
                event_type="action_observed",
                decision="permit",
                reason="observe_mode",
                workspace_id="ws_main",
                agent_id="agent_release",
                grant_id="",
                grant_ref="",
                action="read",
                resource=f"repo/item/{index}",
                scope_attempted=f"read:repo/item/{index}",
                scope_matched=None,
                boundary_id=None,
                runtime=None,
                boundary_type=None,
                created_at=NOW,
            )
        )
        conn.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(40)))

    conn = connect_postgres(DSN)
    rows = conn.execute(
        "SELECT seq, prev_hash, row_hash FROM audit_events ORDER BY seq"
    ).fetchall()
    assert [row[0] for row in rows] == list(range(1, 41))
    assert all(rows[index][1] == rows[index - 1][2] for index in range(1, len(rows)))
    conn.close()
