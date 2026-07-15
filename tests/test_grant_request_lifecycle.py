from __future__ import annotations

import contextlib
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import vinctor_service.grant_requests as grant_requests_module
from vinctor_service import (
    GrantRequestCreateRequest,
    GrantRequestDecisionResult,
    SQLiteV1Service,
    V1EnforceRequest,
)
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def connect_db(tmp_path: Path) -> sqlite3.Connection:
    return connect_sqlite(tmp_path / "vinctor.sqlite")


def create_request(
    *,
    scopes: tuple[str, ...] = ("execute:ci/test",),
    ttl_seconds: int = 3600,
    request_id: str = "grq_main",
) -> GrantRequestCreateRequest:
    return GrantRequestCreateRequest(
        workspace_id="ws_main",
        requester_agent_id="agent_runner",
        requested_scopes=scopes,
        requested_ttl_seconds=ttl_seconds,
        reason="run the CI validation task",
        request_id=request_id,
    )


def audit_events(conn: sqlite3.Connection) -> list[str]:
    return [
        row[0]
        for row in conn.execute(
            "SELECT event_type FROM audit_events ORDER BY rowid"
        ).fetchall()
    ]


def audit_event_decisions(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    return conn.execute(
        """
        SELECT event_type, decision
        FROM audit_events
        ORDER BY rowid
        """
    ).fetchall()


def test_agent_can_create_pending_grant_request(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)

    created = service.create_grant_request(create_request(), now=NOW)

    assert created.status == "created"
    assert created.request is not None
    assert created.request.status == "pending"
    assert created.request.requester_agent_id == "agent_runner"
    assert created.request.target_agent_id == "agent_runner"
    assert service.lookup_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
    ) == created.request
    assert audit_events(conn) == ["grant_requested"]
    conn.close()


def test_workspace_approval_issues_grant_and_enforce_can_consume_it(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.create_grant_request(create_request(), now=NOW)

    approved = service.approve_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason="CI task is expected",
        now=NOW + timedelta(seconds=1),
    )

    assert approved.status == "approved"
    assert approved.request is not None
    assert approved.grant is not None
    assert approved.request.status == "approved"
    assert approved.request.issued_grant_ref == approved.grant.grant_ref
    assert approved.grant.scopes == ("execute:ci/test",)

    enforced = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_main",
            agent_id="agent_runner",
            grant_ref=approved.grant.grant_ref,
            action="execute",
            resource="ci/test",
        ),
        now=NOW + timedelta(seconds=2),
    )

    assert enforced.status_code == 200
    assert enforced.decision == "permit"
    assert audit_events(conn) == [
        "grant_requested",
        "grant_issued",
        "grant_request_approved",
        "action_permitted",
    ]
    conn.close()


def test_workspace_rejection_keeps_request_without_grant(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.create_grant_request(create_request(), now=NOW)

    rejected = service.reject_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason="not needed for this task",
        now=NOW + timedelta(seconds=1),
    )

    assert rejected.status == "rejected"
    assert rejected.request is not None
    assert rejected.request.status == "rejected"
    assert rejected.request.issued_grant_ref is None
    assert service.list_grant_requests(workspace_id="ws_main") == (rejected.request,)
    assert audit_events(conn) == ["grant_requested", "grant_request_rejected"]
    assert audit_event_decisions(conn) == [
        ("grant_requested", "permit"),
        ("grant_request_rejected", "deny"),
    ]
    conn.close()


def test_approval_fails_when_requested_scope_is_outside_bounds(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.create_grant_request(
        create_request(scopes=("execute:deploy/production",)),
        now=NOW,
    )

    failed = service.approve_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason="attempt approval",
        now=NOW + timedelta(seconds=1),
    )

    assert failed.status == "failed"
    assert failed.reason == "scope_outside_issuable_bounds"
    assert failed.grant is None
    assert service.lookup_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
    ).status == "pending"
    # ADR 0008: the approval's out-of-bounds issuance attempt is recorded.
    assert audit_events(conn) == ["grant_requested", "grant_issue_rejected"]
    conn.close()


def test_decided_grant_request_cannot_be_decided_again(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.create_grant_request(create_request(), now=NOW)
    service.reject_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason=None,
        now=NOW + timedelta(seconds=1),
    )

    second = service.reject_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason=None,
        now=NOW + timedelta(seconds=2),
    )

    assert second.status == "failed"
    assert second.reason == "grant_request_not_pending"
    conn.close()


def test_concurrent_approvals_issue_exactly_one_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    setup_conn = connect_sqlite(str(db_path))
    setup = SQLiteV1Service(setup_conn)
    setup.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    setup.create_grant_request(create_request(), now=NOW)
    setup_conn.close()

    real_issue_grant = grant_requests_module.issue_grant
    barrier = threading.Barrier(2)

    def rendezvous_issue_grant(request: object, **kwargs: object) -> object:
        # Force both approvals past the pending check BEFORE either issues a
        # grant: on unserialized code this deterministically produces two live
        # grants. When decisions serialize correctly the loser never reaches
        # issuance, the barrier times out, and the winner proceeds alone.
        with contextlib.suppress(threading.BrokenBarrierError):
            barrier.wait(timeout=2)
        return real_issue_grant(request, **kwargs)

    monkeypatch.setattr(grant_requests_module, "issue_grant", rendezvous_issue_grant)

    def approve(decided_by: str) -> GrantRequestDecisionResult:
        conn = connect_sqlite(str(db_path), timeout=10)
        try:
            worker = SQLiteV1Service(conn, initialize_schema=False)
            return worker.approve_grant_request(
                request_id="grq_main",
                workspace_id="ws_main",
                decided_by=decided_by,
                decision_reason=None,
                now=NOW + timedelta(seconds=1),
            )
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(approve, "operator:a"), pool.submit(approve, "operator:b")]
        results = [future.result(timeout=30) for future in futures]

    assert sorted(result.status for result in results) == ["approved", "failed"]
    winner = next(result for result in results if result.status == "approved")
    loser = next(result for result in results if result.status == "failed")
    assert loser.reason == "grant_request_not_pending"
    assert loser.grant is None

    check = SQLiteV1Service(connect_sqlite(str(db_path)), initialize_schema=False)
    active = check.list_grants(workspace_id="ws_main", agent_id="agent_runner", status="active")
    assert len(active) == 1
    request = check.lookup_grant_request(request_id="grq_main", workspace_id="ws_main")
    assert request is not None
    assert request.status == "approved"
    assert request.issued_grant_ref == active[0].grant_ref == winner.grant.grant_ref
    check.conn.close()


def _decision_race_invariants(
    service: SQLiteV1Service, results: tuple[GrantRequestDecisionResult, ...]
) -> None:
    decided = [result for result in results if result.status in ("approved", "rejected")]
    assert len(decided) == 1
    losers = [result for result in results if result.status == "failed"]
    assert len(losers) == 1
    assert losers[0].reason == "grant_request_not_pending"
    assert losers[0].grant is None

    final = service.lookup_grant_request(request_id="grq_main", workspace_id="ws_main")
    assert final is not None
    active = service.list_grants(workspace_id="ws_main", status="active")
    if final.status == "approved":
        assert len(active) == 1
        assert final.issued_grant_ref == active[0].grant_ref
    else:
        # Never a rejected request that nevertheless has a live grant.
        assert final.status == "rejected"
        assert final.issued_grant_ref is None
        assert active == ()


def test_reject_racing_approve_cannot_orphan_a_live_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.create_grant_request(create_request(), now=NOW)

    repository = service.grant_request_repository
    real_get_request = repository.get_request
    interleaved: dict[str, object] = {}

    def get_request_spy(request_id: str) -> object:
        current = real_get_request(request_id)
        if "result" not in interleaved:
            # A rival approval completes between the reject's pending check
            # and its status write.
            interleaved["result"] = None
            interleaved["result"] = service.approve_grant_request(
                request_id="grq_main",
                workspace_id="ws_main",
                decided_by="operator:racer",
                decision_reason=None,
                now=NOW + timedelta(seconds=1),
            )
        return current

    monkeypatch.setattr(repository, "get_request", get_request_spy)
    reject_result = service.reject_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason="not needed",
        now=NOW + timedelta(seconds=2),
    )
    monkeypatch.undo()

    _decision_race_invariants(service, (interleaved["result"], reject_result))
    conn.close()


def test_approve_racing_reject_yields_a_single_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.create_grant_request(create_request(), now=NOW)

    repository = service.grant_request_repository
    real_get_request = repository.get_request
    interleaved: dict[str, object] = {}

    def get_request_spy(request_id: str) -> object:
        current = real_get_request(request_id)
        if "result" not in interleaved:
            # A rival rejection completes between the approval's pending check
            # and its grant issuance: the approval must lose WITHOUT leaving a
            # live grant behind.
            interleaved["result"] = None
            interleaved["result"] = service.reject_grant_request(
                request_id="grq_main",
                workspace_id="ws_main",
                decided_by="operator:racer",
                decision_reason=None,
                now=NOW + timedelta(seconds=1),
            )
        return current

    monkeypatch.setattr(repository, "get_request", get_request_spy)
    approve_result = service.approve_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason="looks fine",
        now=NOW + timedelta(seconds=2),
    )
    monkeypatch.undo()

    _decision_race_invariants(service, (interleaved["result"], approve_result))
    conn.close()
