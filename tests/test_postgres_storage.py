from __future__ import annotations

import json
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
from vinctor_service.audit_chain import GENESIS_PREV_HASH, AnchorRecord
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


def test_postgres_replay_flood_cannot_evict_fresh_nonce() -> None:
    # SECURITY (ADR 0007): never evict a still-fresh nonce to make room. An
    # attacker who captured a valid proof must not be able to flood the same
    # token's per-token cap with fresh nonces to push the captured nonce out
    # and replay it inside the freshness window.
    assert DSN is not None
    conn = connect_postgres(DSN)
    cap = 3
    store = PostgresReplayStore(conn, max_entries=100, max_per_token=cap)
    # The captured proof's nonce: oldest ts in the window (still fresh).
    assert store.check_and_record(
        token_id="vtk_main", nonce="n1", ts=99, now_unix=100, skew=30
    )
    # Attacker pushes `cap` more distinct fresh nonces for the SAME token.
    for i in range(cap):
        store.check_and_record(
            token_id="vtk_main", nonce=f"flood{i}", ts=100, now_unix=100, skew=30
        )
    # Re-presenting the captured nonce within the window MUST still be a
    # replay: n1 was never evicted to make room for the flood.
    assert not store.check_and_record(
        token_id="vtk_main", nonce="n1", ts=99, now_unix=100, skew=30
    )
    # Cap full of still-fresh nonces -> a brand-new nonce is rejected
    # (fail closed), never evicting a live entry.
    assert not store.check_and_record(
        token_id="vtk_main", nonce="brand_new", ts=100, now_unix=100, skew=30
    )
    # Expired entries are still purged: the next window frees capacity, so the
    # store stays bounded and the token is not locked out forever.
    assert store.check_and_record(
        token_id="vtk_main", nonce="next_window", ts=200, now_unix=200, skew=30
    )
    conn.close()


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


def test_postgres_unrelated_setting_does_not_drop_workspace_token_and_pop_mandates() -> None:
    # SECURITY: an unrelated agent-level setting must NOT silently disable a
    # workspace-wide require_subject_token / require_pop mandate. The shared
    # settings row means "a row exists" was misread as "the agent explicitly
    # set the mandate = its default false". Presence-bit gated.
    assert DSN is not None
    conn = connect_postgres(DSN)
    repo = PostgresAgentEnforcementSettingsRepository(conn)
    repo.set_require_subject_token(
        workspace_id="ws_main", agent_id="", require_subject_token=True, now=NOW
    )
    repo.set_require_pop(workspace_id="ws_main", agent_id="", require_pop=True, now=NOW)
    repo.set_require_boundary(
        workspace_id="ws_main", agent_id="agent_bound", require_boundary=False, now=NOW
    )

    assert repo.is_subject_token_required(
        workspace_id="ws_main", agent_id="agent_bound"
    ) is True
    assert repo.is_pop_required(workspace_id="ws_main", agent_id="agent_bound") is True
    conn.close()


def test_postgres_explicit_subject_token_false_still_exempts() -> None:
    # The presence bit must still let an operator EXPLICITLY exempt an agent.
    assert DSN is not None
    conn = connect_postgres(DSN)
    repo = PostgresAgentEnforcementSettingsRepository(conn)
    repo.set_require_subject_token(
        workspace_id="ws_main", agent_id="", require_subject_token=True, now=NOW
    )
    repo.set_require_subject_token(
        workspace_id="ws_main",
        agent_id="agent_exempt",
        require_subject_token=False,
        now=NOW,
    )

    assert repo.is_subject_token_required(
        workspace_id="ws_main", agent_id="agent_exempt"
    ) is False
    conn.close()


def test_postgres_enforcement_presence_migration_fail_closed() -> None:
    # Upgrade path: recreate agent_enforcement_settings at the old schema
    # (no *_set presence columns), seed rows, clear the version-5 gate, and
    # re-run init_postgres_schema. Migrated rows must be fail-closed: a value
    # counts as explicitly set only where it is already TRUE.
    assert DSN is not None
    conn = connect_postgres(DSN)
    with conn.transaction():
        conn.execute("DROP TABLE agent_enforcement_settings")
        conn.execute(
            """
            CREATE TABLE agent_enforcement_settings (
                workspace_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                require_boundary BOOLEAN NOT NULL DEFAULT FALSE,
                require_subject_token BOOLEAN NOT NULL DEFAULT FALSE,
                require_pop BOOLEAN NOT NULL DEFAULT FALSE,
                updated_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (workspace_id, agent_id)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO agent_enforcement_settings
                (workspace_id, agent_id, require_boundary, require_subject_token,
                 require_pop, updated_at)
            VALUES ('ws_main', '', TRUE, TRUE, TRUE, %s),
                   ('ws_main', 'agent_subject', FALSE, TRUE, FALSE, %s),
                   ('ws_main', 'agent_boundary', TRUE, FALSE, FALSE, %s)
            """,
            (NOW, NOW, NOW),
        )
        conn.execute("DELETE FROM schema_migrations WHERE version = 5")

    init_postgres_schema(conn)
    repo = PostgresAgentEnforcementSettingsRepository(conn)

    # (a) A row that had require_subject_token=TRUE still reads as required.
    assert repo.is_subject_token_required(
        workspace_id="ws_main", agent_id="agent_subject"
    ) is True
    # (b) A row that only ever had an unrelated mandate must not drop the
    # workspace require_subject_token / require_pop mandates.
    assert repo.is_subject_token_required(
        workspace_id="ws_main", agent_id="agent_boundary"
    ) is True
    assert repo.is_pop_required(
        workspace_id="ws_main", agent_id="agent_boundary"
    ) is True
    assert repo.is_boundary_required(
        workspace_id="ws_main", agent_id="agent_boundary"
    ) is True
    # (c) The require_boundary_set realignment stops a subject-token-only row
    # from overriding the workspace boundary mandate.
    assert repo.is_boundary_required(
        workspace_id="ws_main", agent_id="agent_subject"
    ) is True
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


def test_postgres_policy_apply_is_all_or_nothing_and_workspace_locked(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vinctor_service.postgres_policy import (
        POLICY_APPLY_LOCK_CLASSID,
        _snapshot_state,
        _workspace_apply_lock_key,
    )

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
    # Snapshot consistency: the recorded snapshot equals the live policy state.
    row = conn.execute(
        "SELECT snapshot_json FROM policy_versions WHERE workspace_id = %s AND version = %s",
        ("ws_main", first.policy_version),
    ).fetchone()
    stored = json.loads(row[0]) if isinstance(row[0], str) else row[0]
    assert stored == _snapshot_state(service=service, workspace_id="ws_main")

    before = (
        service.scope_bounds_repository.list_bounds_for_workspace("ws_main"),
        service.list_auto_approval_rules("ws_main"),
        service.agent_enforcement_settings_repository.list_require_boundary("ws_main"),
        list_policy_versions(service=service, workspace_id="ws_main"),
    )

    second_path = tmp_path / "second.yaml"
    second_path.write_text(
        """
version: 1
workspace_id: ws_main
agent_bounds:
  - agent_id: agent_a
    scopes: [write:repo/a/elevated]
  - agent_id: agent_b
    scopes: [write:repo/b]
auto_approval_rules:
  - rule_id: apr_old
    name: old
    target_agent_id: agent_a
    allowed_scopes: [write:repo/a/elevated]
    max_ttl: 9m
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

    observed: dict[str, object] = {}

    # The boundary write is the LAST write step before the version record; by
    # the time it runs, the bounds and rule writes have already happened
    # inside the apply transaction.
    def boom(**_kwargs: object) -> None:
        rival = connect_postgres(DSN)
        try:
            observed["advisory_lock"] = rival.execute(
                """
                SELECT granted FROM pg_locks
                WHERE locktype = 'advisory' AND classid::int8 = %s AND objid::int8 = %s
                """,
                (POLICY_APPLY_LOCK_CLASSID, _workspace_apply_lock_key("ws_main")),
            ).fetchone()
            observed["rival_sees_agent_b"] = rival.execute(
                """
                SELECT COUNT(*) FROM agent_issuable_scope_bounds
                WHERE workspace_id = %s AND agent_id = %s
                """,
                ("ws_main", "agent_b"),
            ).fetchone()[0]
        finally:
            rival.close()
        raise RuntimeError("boundary write failed")

    monkeypatch.setattr(
        service.agent_enforcement_settings_repository, "set_require_boundary", boom
    )
    with pytest.raises(RuntimeError, match="boundary write failed"):
        apply_policy_file(
            second_path,
            service=service,
            workspace_id="ws_main",
            applied_by="operator:b",
            now=NOW,
        )

    # The whole apply ran under the workspace advisory lock, and no other
    # connection ever observed the half-applied writes.
    assert observed["advisory_lock"] == (True,)
    assert observed["rival_sees_agent_b"] == 0
    # All-or-nothing: every earlier write plus the version record unwound.
    after = (
        service.scope_bounds_repository.list_bounds_for_workspace("ws_main"),
        service.list_auto_approval_rules("ws_main"),
        service.agent_enforcement_settings_repository.list_require_boundary("ws_main"),
        list_policy_versions(service=service, workspace_id="ws_main"),
    )
    assert after == before
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
            "generalized": False,
            "evidence": {"enforced": 0, "observed": 1, "simulated": 0},
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


def _pg_audit_event(event_id: str) -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        event_type="action_permitted",
        decision="permit",
        reason="ok",
        workspace_id="ws_main",
        agent_id="agent_a",
        grant_id="grnt_1",
        grant_ref="grt_1",
        action="read",
        resource="repo/x",
        scope_attempted="read:repo/x",
        scope_matched="read:repo/*",
        boundary_id="bnd_1",
        runtime="claude-code",
        boundary_type="pretooluse",
        created_at=NOW,
    )


def _seed_pg_chain(conn, count: int = 3) -> PostgresAuditWriter:
    writer = PostgresAuditWriter(conn)
    for i in range(1, count + 1):
        writer.write(_pg_audit_event(f"evt_{i}"))
    return writer


def test_postgres_audit_verify_ok_on_untouched_chain() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    writer = _seed_pg_chain(conn)
    v = writer.verify_chain()
    assert v.ok is True and v.count == 3 and v.head_seq == 3
    assert writer.chain_head()[0] == 3
    conn.close()


def test_postgres_audit_verify_detects_modified_event_json() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    writer = _seed_pg_chain(conn)
    forged = json.dumps(
        {**_pg_audit_event("evt_2").to_dict(), "decision": "deny"}, sort_keys=True
    )
    with conn.transaction():
        conn.execute("UPDATE audit_events SET event_json = %s WHERE seq = 2", (forged,))
    v = writer.verify_chain()
    assert v.ok is False and v.break_seq == 2 and v.break_kind == "modified"
    conn.close()


def test_postgres_audit_verify_detects_deleted_row() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    writer = _seed_pg_chain(conn)
    with conn.transaction():
        conn.execute("DELETE FROM audit_events WHERE seq = 2")
    v = writer.verify_chain()
    assert v.ok is False and v.break_kind == "deleted" and v.break_seq == 2
    conn.close()


def test_postgres_audit_verify_detects_column_mismatch() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    writer = _seed_pg_chain(conn)
    # Edit only the denormalized filter column, leaving event_json (and its hash) intact.
    with conn.transaction():
        conn.execute("UPDATE audit_events SET workspace_id = 'ws_other' WHERE seq = 2")
    v = writer.verify_chain()
    assert v.ok is False and v.break_kind == "column_mismatch" and v.break_seq == 2
    conn.close()


def test_postgres_audit_chain_head_reports_tip_and_genesis_when_empty() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    writer = PostgresAuditWriter(conn)
    assert writer.chain_head() == (0, GENESIS_PREV_HASH)
    writer.write(_pg_audit_event("evt_1"))
    seq, head_hash = writer.chain_head()
    assert seq == 1 and len(head_hash) == 64
    conn.close()


def test_postgres_audit_verify_against_anchor_ok_and_detects_missing() -> None:
    assert DSN is not None
    conn = connect_postgres(DSN)
    writer = _seed_pg_chain(conn)
    anchors = [
        AnchorRecord(
            seq=s,
            row_hash=conn.execute(
                "SELECT row_hash FROM audit_events WHERE seq = %s", (s,)
            ).fetchone()[0],
        )
        for s in (1, 2, 3)
    ]
    assert writer.verify_against_anchor(anchors).ok is True
    # A row covered by an external anchor is later deleted: verify_chain() alone
    # would report a shorter but self-consistent chain, while the anchor catches it.
    with conn.transaction():
        conn.execute("DELETE FROM audit_events WHERE seq = 3")
    result = writer.verify_against_anchor(anchors)
    assert (
        result.ok is False
        and result.divergence_seq == 3
        and result.divergence_kind == "missing"
    )
    conn.close()


def _pg_full_audit_event(event_id: str) -> AuditEvent:
    # Every optional/ADR-0007/ADR-0008 field populated, so all Postgres-only
    # materialized columns are non-NULL and the crosscheck normalization paths
    # (TIMESTAMPTZ round-trip, BOOLEAN, INTEGER, nullable TEXT) are exercised.
    return replace(
        _pg_audit_event(event_id),
        enforcing_principal="usr_owner",
        reason_code="unmapped_action",
        occurrence_count=4,
        first_seen_at=NOW - timedelta(minutes=30),
        last_seen_at=NOW - timedelta(minutes=1),
        identity_proven=True,
        token_id="stk_1",
    )


def _seed_pg_chain_with_full_event(conn) -> PostgresAuditWriter:
    writer = PostgresAuditWriter(conn)
    writer.write(_pg_audit_event("evt_1"))
    writer.write(_pg_full_audit_event("evt_2"))
    writer.write(_pg_audit_event("evt_3"))
    return writer


def test_postgres_audit_verify_ok_with_all_optional_columns_populated() -> None:
    # Positive normalization guard: a healthy chain whose row has every
    # materialized column populated (datetimes come back as tz-aware datetimes,
    # identity_proven as BOOLEAN, occurrence_count as INTEGER) must still verify.
    assert DSN is not None
    conn = connect_postgres(DSN)
    writer = _seed_pg_chain_with_full_event(conn)
    v = writer.verify_chain()
    assert v.ok is True and v.count == 3 and v.head_seq == 3
    conn.close()


@pytest.mark.parametrize(
    ("column", "tampered_value"),
    [
        ("created_at", NOW + timedelta(hours=6)),
        ("enforcing_principal", "usr_forged"),
        ("reason_code", "forged_code"),
        ("occurrence_count", 999),
        ("first_seen_at", NOW - timedelta(days=2)),
        ("last_seen_at", NOW + timedelta(days=2)),
        ("identity_proven", False),
        ("token_id", "stk_forged"),
    ],
)
def test_postgres_audit_verify_detects_materialized_column_tamper(
    column: str, tampered_value: object
) -> None:
    # list_filtered reads these materialized columns directly, so an attacker who
    # edits ONLY the column (event_json and row_hash intact) could hide or
    # re-classify an event. verify_chain must cross-check every one of them.
    assert DSN is not None
    conn = connect_postgres(DSN)
    writer = _seed_pg_chain_with_full_event(conn)
    with conn.transaction():
        conn.execute(
            f"UPDATE audit_events SET {column} = %s WHERE seq = 2",
            (tampered_value,),
        )
    v = writer.verify_chain()
    assert v.ok is False and v.break_kind == "column_mismatch" and v.break_seq == 2
    conn.close()
