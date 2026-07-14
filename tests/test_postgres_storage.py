from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from vinctor_core import (
    BoundaryRegistrationInput,
    disable_boundary,
    register_boundary,
)
from vinctor_core.models import AuditEvent, Grant
from vinctor_service.models import (
    GrantRequest,
    GrantRequestCreateRequest,
    SubjectToken,
    V1EnforceRequest,
    V1ObserveRequest,
)
from vinctor_service.policy_files import (
    apply_policy_file,
    list_policy_versions,
    rollback_policy_version,
)
from vinctor_service.policy_infer import infer_policy_document
from vinctor_service.postgres import (
    PostgresAgentEnforcementSettingsRepository,
    PostgresAuditWriter,
    PostgresBoundaryRegistry,
    PostgresGrantRepository,
    PostgresV1Service,
    connect_postgres,
    init_postgres_schema,
)
from vinctor_service.postgres_control import (
    PostgresGrantRequestRepository,
    PostgresLocalKeyRepository,
    PostgresReplayStore,
    PostgresSubjectTokenRepository,
)
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.service_runtime import prepare_service_runtime
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
        conn.execute(
            "TRUNCATE TABLE pop_replay_nonces, subject_tokens, grant_requests, "
            "local_keys, audit_events, grants, boundaries, agent_enforcement_settings, "
            "agent_issuable_scope_bounds, auto_approval_rules, policy_versions"
        )
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


def test_postgres_local_key_repository_contract() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    repository = PostgresLocalKeyRepository(conn)

    workspace = repository.create_workspace_key(
        workspace_id="ws_main", raw_key="wsk_main", key_id="lkey_workspace", now=NOW
    )
    agent = repository.create_agent_key(
        workspace_id="ws_main", agent_id="agent_release", raw_key="aak_main",
        key_id="lkey_agent", now=NOW,
    )
    pep = repository.create_pep_key(
        workspace_id="ws_main", pep_id="pep_release", raw_key="pep_main",
        key_id="lkey_pep", now=NOW,
    )

    assert repository.resolve_workspace_identity("wsk_main", now=NOW).workspace_id == "ws_main"
    assert repository.resolve_agent_identity("aak_main", now=NOW).agent_id == "agent_release"
    assert repository.resolve_pep_identity("pep_main", now=NOW).pep_id == "pep_release"
    assert repository.resolve_agent_identity("wsk_main", now=NOW) is None
    assert {record.key_id for record in repository.list_for_workspace("ws_main")} == {
        workspace.record.key_id,
        agent.record.key_id,
        pep.record.key_id,
    }
    revoked = repository.revoke_key(agent.record.key_id, now=NOW + timedelta(seconds=1))
    assert revoked is not None and revoked.status == "revoked"
    assert repository.resolve_agent_identity("aak_main", now=NOW) is None
    conn.close()


def test_postgres_grant_request_and_subject_token_repository_contracts() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    requests = PostgresGrantRequestRepository(conn)
    tokens = PostgresSubjectTokenRepository(conn)
    request = GrantRequest(
        request_id="grq_main", workspace_id="ws_main",
        requester_agent_id="agent_release", target_agent_id="agent_release",
        requested_scopes=("write:repo/feature/*",), requested_ttl_seconds=300,
        reason="release", status="pending", created_at=NOW,
    )
    token = SubjectToken(
        token_id="vtk_main", token_hash="hash_main", workspace_id="ws_main",
        agent_id="agent_release", grant_ref="grt_main", audience="pep_release",
        issued_at=NOW, expires_at=NOW + timedelta(minutes=5),
        created_by="agent_release", pop_secret="secret",
    )

    requests.insert_request(request)
    decided = replace(
        request, status="approved", decided_at=NOW, decided_by="operator:main",
        issued_grant_ref="grt_main",
    )
    requests.update_request(decided)
    tokens.insert(token)

    assert requests.get_request("grq_main") == decided
    assert requests.list_requests_for_workspace("ws_main") == (decided,)
    assert tokens.get_by_hash("hash_main") == token
    assert tokens.get_by_id("vtk_main") == replace(token, pop_secret=None)
    assert tokens.list_subject_tokens("ws_main") == (replace(token, pop_secret=None),)
    assert tokens.revoke("vtk_main", now=NOW + timedelta(seconds=1))
    assert tokens.get_by_id("vtk_main").revoked_at == NOW + timedelta(seconds=1)
    conn.close()


def test_postgres_replay_store_rejects_cross_instance_duplicate() -> None:
    assert DSN is not None
    first_conn = connect_postgres(DSN)
    second_conn = connect_postgres(DSN)
    first = PostgresReplayStore(first_conn)
    second = PostgresReplayStore(second_conn)

    assert first.check_and_record(
        token_id="vtk_main", nonce="nonce_main", ts=100, now_unix=100, skew=30
    )
    assert not second.check_and_record(
        token_id="vtk_main", nonce="nonce_main", ts=100, now_unix=100, skew=30
    )
    first_conn.close()
    second_conn.close()


def test_postgres_full_runtime_shares_control_plane_across_instances() -> None:
    assert DSN is not None
    config = ServiceRuntimeConfig(
        storage_backend="postgres", postgres_dsn=DSN, port=0,
        service_mode="self_hosted",
    )
    first = prepare_service_runtime(config, clock=lambda: NOW)
    second = prepare_service_runtime(config, clock=lambda: NOW)
    try:
        first.key_repository.create_agent_key(
            workspace_id="ws_main", agent_id="agent_release", raw_key="aak_main",
            now=NOW,
        )
        assert second.key_repository.resolve_agent_identity(
            "aak_main", now=NOW
        ).agent_id == "agent_release"
        first.service.set_agent_issuable_scope_bounds(
            workspace_id="ws_main", agent_id="agent_release",
            scopes=("write:repo/feature/*",), max_ttl_seconds=300, now=NOW,
        )
        created = first.service.create_grant_request(
            GrantRequestCreateRequest(
                workspace_id="ws_main", requester_agent_id="agent_release",
                requested_scopes=("write:repo/feature/*",),
                requested_ttl_seconds=300, reason="release", request_id="grq_main",
            ),
            now=NOW,
        )
        approved = second.service.approve_grant_request(
            request_id="grq_main", workspace_id="ws_main",
            decided_by="operator:main", decision_reason=None, now=NOW,
        )
        minted = first.service.mint_subject_token(
            workspace_id="ws_main", agent_id="agent_release",
            grant_ref=approved.grant.grant_ref, audience="pep_release",
            ttl_seconds=60, now=NOW,
        )

        assert created.status == "created"
        assert approved.status == "approved"
        assert minted.status == "minted"
        assert second.service.subject_token_repository.get_by_id(minted.token_id) is not None
    finally:
        first.close()
        second.close()


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


def test_postgres_boundary_and_settings_drive_enforcement() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    service = PostgresV1Service(conn)
    service.insert_grant(grant())
    service.agent_enforcement_settings_repository.set_require_boundary(
        workspace_id="ws_main",
        agent_id="",
        require_boundary=True,
        now=NOW,
    )

    missing = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            grant_ref="grt_main",
            action="write",
            resource="repo/feature/readme",
        ),
        now=NOW,
    )
    boundary = register_boundary(
        service.boundary_registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        boundary_id="bnd_main",
        now=NOW,
    )
    permit = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            grant_ref="grt_main",
            action="write",
            resource="repo/feature/readme",
            boundary_id=boundary.boundary_id,
        ),
        now=NOW,
    )
    disable_boundary(
        service.boundary_registry,
        boundary_id=boundary.boundary_id,
        workspace_id="ws_main",
        now=NOW + timedelta(seconds=1),
    )
    disabled = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            grant_ref="grt_main",
            action="write",
            resource="repo/feature/readme",
            boundary_id=boundary.boundary_id,
        ),
        now=NOW + timedelta(seconds=1),
    )

    assert missing.error == "boundary_required"
    assert permit.status_code == 200
    event = service.get_audit_event(permit.audit_event_id or "")
    assert event is not None
    assert event.runtime == "claude-code"
    assert disabled.error == "boundary_inactive"
    conn.close()


def test_postgres_enforcement_setting_agent_override() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    repo = PostgresAgentEnforcementSettingsRepository(conn)
    repo.set_require_boundary(
        workspace_id="ws_main", agent_id="", require_boundary=True, now=NOW
    )
    repo.set_require_boundary(
        workspace_id="ws_main",
        agent_id="agent_exempt",
        require_boundary=False,
        now=NOW,
    )

    assert repo.is_boundary_required(workspace_id="ws_main", agent_id="agent_other")
    assert not repo.is_boundary_required(
        workspace_id="ws_main", agent_id="agent_exempt"
    )
    assert repo.list_require_boundary("ws_main") == (
        ("", True),
        ("agent_exempt", False),
    )
    conn.close()


def test_postgres_unrelated_setting_does_not_override_workspace_boundary() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    repo = PostgresAgentEnforcementSettingsRepository(conn)
    repo.set_require_boundary(
        workspace_id="ws_main", agent_id="", require_boundary=True, now=NOW
    )
    repo.set_require_subject_token(
        workspace_id="ws_main",
        agent_id="agent_subject",
        require_subject_token=True,
        now=NOW,
    )

    assert repo.is_boundary_required(workspace_id="ws_main", agent_id="agent_subject")
    conn.close()


def test_postgres_policy_apply_versions_and_exact_rollback(tmp_path) -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    service = PostgresV1Service(conn)
    first_path = tmp_path / "first.yaml"
    first_path.write_text(
        """
version: 1
workspace_id: ws_main
agent_bounds:
  - agent_id: agent_a
    scopes: [read:repo/a]
auto_approval_rules:
  - rule_id: apr_old
    name: old
    target_agent_id: agent_a
    allowed_scopes: [read:repo/a]
    max_ttl: 5m
require_boundary:
  workspace: true
""".strip(),
        encoding="utf-8",
    )
    first = apply_policy_file(
        first_path,
        service=service,
        workspace_id="ws_main",
        applied_by="operator:a",
        now=NOW,
    )
    second_path = tmp_path / "second.yaml"
    second_path.write_text(
        """
version: 1
workspace_id: ws_main
agent_bounds:
  - agent_id: agent_b
    scopes: [write:repo/b]
auto_approval_rules:
  - rule_id: apr_new
    name: new
    target_agent_id: agent_b
    allowed_scopes: [write:repo/b]
    max_ttl: 10m
require_boundary:
  workspace: false
""".strip(),
        encoding="utf-8",
    )
    apply_policy_file(
        second_path,
        service=service,
        workspace_id="ws_main",
        applied_by="operator:b",
        now=NOW,
    )
    service.agent_enforcement_settings_repository.set_require_subject_token(
        workspace_id="ws_main",
        agent_id="agent_subject",
        require_subject_token=True,
        now=NOW,
    )

    result = rollback_policy_version(
        service=service,
        workspace_id="ws_main",
        version=first.policy_version,
        applied_by="operator:rollback",
        now=NOW,
    )

    assert result.policy_version == 3
    assert service.scope_bounds_repository.list_bounds_for_workspace("ws_main") == (
        ("agent_a", ("read:repo/a",)),
    )
    assert [rule.rule_id for rule in service.list_auto_approval_rules("ws_main")] == [
        "apr_old"
    ]
    assert service.agent_enforcement_settings_repository.is_subject_token_required(
        workspace_id="ws_main", agent_id="agent_subject"
    )
    assert service.agent_enforcement_settings_repository.is_boundary_required(
        workspace_id="ws_main", agent_id="agent_subject"
    )
    assert [item.action for item in list_policy_versions(
        service=service, workspace_id="ws_main"
    )] == ["apply", "apply", "rollback"]
    conn.close()


def test_postgres_boundary_name_is_unique_per_workspace() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    registry = PostgresBoundaryRegistry(conn)
    registration = BoundaryRegistrationInput(
        workspace_id="ws_main",
        name="claude-code",
        runtime="claude-code",
        boundary_type="pretooluse",
    )
    first = register_boundary(registry, registration, boundary_id="bnd_one", now=NOW)

    with pytest.raises(ValueError, match="boundary name must be unique"):
        register_boundary(registry, registration, boundary_id="bnd_two", now=NOW)

    assert registry.get(first.boundary_id) == first
    assert registry.list_for_workspace("ws_main") == [first]
    conn.close()


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
