from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_core import Grant
from vinctor_service import SQLiteGrantRepository, init_sqlite_schema, insert_grant
from vinctor_service.repositories import InMemoryGrantRepository
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 6, 11, 12, 0, tzinfo=UTC)


def grant(
    grant_ref: str,
    *,
    grant_id: str | None = None,
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
    status: str = "active",
) -> Grant:
    return Grant(
        grant_id=grant_id or grant_ref.replace("grt", "grnt"),
        grant_ref=grant_ref,
        workspace_id=workspace_id,
        agent_id=agent_id,
        scopes=("write:repo/feature/*",),
        status=status,
        expires_at=NOW + timedelta(hours=1),
    )


def test_in_memory_lists_grants_for_workspace_with_filters() -> None:
    repository = InMemoryGrantRepository(
        (
            grant("grt_a", grant_id="grnt_a"),
            grant("grt_b", grant_id="grnt_b", agent_id="agent_other"),
            grant("grt_c", grant_id="grnt_c", status="revoked"),
            grant("grt_d", grant_id="grnt_d", workspace_id="ws_other"),
        )
    )

    assert [
        grant.grant_ref
        for grant in repository.list_grants_for_workspace("ws_main")
    ] == ["grt_a", "grt_b", "grt_c"]
    assert [
        grant.grant_ref
        for grant in repository.list_grants_for_workspace(
            "ws_main",
            agent_id="agent_release",
            status="active",
        )
    ] == ["grt_a"]
    assert repository.list_grants_for_workspace("ws_missing") == ()


def test_sqlite_lists_grants_for_workspace_with_filters(tmp_path: Path) -> None:
    conn = connect_sqlite(tmp_path / "vinctor.sqlite")
    init_sqlite_schema(conn)
    insert_grant(conn, grant("grt_a", grant_id="grnt_a"))
    insert_grant(conn, grant("grt_b", grant_id="grnt_b", agent_id="agent_other"))
    insert_grant(conn, grant("grt_c", grant_id="grnt_c", status="revoked"))
    insert_grant(conn, grant("grt_d", grant_id="grnt_d", workspace_id="ws_other"))
    repository = SQLiteGrantRepository(conn)

    assert [
        grant.grant_ref
        for grant in repository.list_grants_for_workspace("ws_main")
    ] == ["grt_a", "grt_b", "grt_c"]
    assert [
        grant.grant_ref
        for grant in repository.list_grants_for_workspace(
            "ws_main",
            agent_id="agent_release",
            status="active",
        )
    ] == ["grt_a"]
    assert repository.list_grants_for_workspace("ws_missing") == ()
    conn.close()
