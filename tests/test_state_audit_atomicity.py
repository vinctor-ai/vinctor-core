"""A4: a state change and its audit row must commit together.

If the audit writer fails, the state change must roll back rather than persist
unrecorded. Power: without the wrapping transaction the state write self-commits
before the audit write is attempted, so the failed audit would leave a persisted
grant/request/token with no audit trail.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vinctor_core.models import Grant
from vinctor_service import (
    GrantIssueRequest,
    GrantRequestCreateRequest,
    SQLiteV1Service,
)
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _service() -> SQLiteV1Service:
    return SQLiteV1Service(connect_sqlite(":memory:"))


def _break_audit(service: SQLiteV1Service) -> None:
    def _raise(*_args, **_kwargs):
        raise RuntimeError("audit write failed")

    service.audit_writer.write = _raise  # type: ignore[method-assign]


def test_issue_grant_rolls_back_when_audit_write_fails() -> None:
    service = _service()
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main", agent_id="agent_a",
        scopes=("execute:ci/test",), now=NOW,
    )
    _break_audit(service)

    with pytest.raises(RuntimeError, match="audit write failed"):
        service.issue_grant(
            GrantIssueRequest(
                workspace_id="ws_main", target_agent_id="agent_a",
                requested_scopes=("execute:ci/test",), ttl_seconds=3600,
                grant_ref="grt_probe",
            ),
            now=NOW,
        )

    assert service.grant_repository.get_by_ref("grt_probe") is None


def test_revoke_grant_rolls_back_when_audit_write_fails() -> None:
    service = _service()
    service.insert_grant(
        Grant(
            grant_id="grnt_seed", grant_ref="grt_seed", workspace_id="ws_main",
            agent_id="agent_a", scopes=("write:repo/x",), status="active",
            expires_at=NOW + timedelta(hours=1),
        )
    )
    _break_audit(service)

    with pytest.raises(RuntimeError, match="audit write failed"):
        service.revoke_grant(grant_ref="grt_seed", workspace_id="ws_main", now=NOW)

    # The grant is still active: the failed audit rolled the revocation back.
    assert service.grant_repository.get_by_ref("grt_seed").status == "active"


def test_create_grant_request_rolls_back_when_audit_write_fails() -> None:
    service = _service()
    _break_audit(service)

    with pytest.raises(RuntimeError, match="audit write failed"):
        service.create_grant_request(
            GrantRequestCreateRequest(
                workspace_id="ws_main", requester_agent_id="agent_a",
                requested_scopes=("execute:ci/test",), requested_ttl_seconds=3600,
                reason="run CI", request_id="grq_probe",
            ),
            now=NOW,
        )

    assert service.grant_request_repository.list_requests_for_workspace("ws_main") == ()


def test_mint_subject_token_rolls_back_when_audit_write_fails() -> None:
    service = _service()
    service.insert_grant(
        Grant(
            grant_id="grnt_seed", grant_ref="grt_seed", workspace_id="ws_main",
            agent_id="agent_a", scopes=("write:repo/x",), status="active",
            expires_at=NOW + timedelta(hours=1),
        )
    )
    _break_audit(service)

    with pytest.raises(RuntimeError, match="audit write failed"):
        service.mint_subject_token(
            workspace_id="ws_main", agent_id="agent_a", grant_ref="grt_seed",
            audience="pep_x", ttl_seconds=300, now=NOW,
        )

    assert service.subject_token_repository.list_subject_tokens("ws_main") == ()
