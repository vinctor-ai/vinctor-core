import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vinctor_service.policy_files import (
    _snapshot_policy_state,
    apply_policy_file,
    list_policy_versions,
    rollback_policy_version,
)
from vinctor_service.sqlite import SQLiteV1Service, get_sqlite_schema_versions

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)

FIRST_POLICY = """
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
"""

# Valid follow-up policy touching every write kind: it re-bounds agent_a,
# adds agent_b, rewrites rule apr_old, adds apr_new, and flips the boundary
# setting. Tests inject a failure part-way through applying THIS document.
SECOND_POLICY = """
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
"""


def _write_policy(path: Path, body: str) -> Path:
    path.write_text(body.strip(), encoding="utf-8")
    return path


def _policy_state(service: SQLiteV1Service) -> tuple[object, object, object, object]:
    return (
        service.scope_bounds_repository.list_bounds_for_workspace("ws_main"),
        service.list_auto_approval_rules(workspace_id="ws_main"),
        service.agent_enforcement_settings_repository.list_require_boundary("ws_main"),
        list_policy_versions(service=service, workspace_id="ws_main"),
    )


def test_policy_apply_records_append_only_versions(tmp_path: Path) -> None:
    service = SQLiteV1Service(sqlite3.connect(":memory:"))
    policy = _write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
workspace_id: ws_main
agent_bounds:
  - agent_id: agent_a
    scopes: [read:repo/a]
""",
    )

    first = apply_policy_file(
        policy, service=service, workspace_id="ws_main", applied_by="operator:a", now=NOW
    )
    second = apply_policy_file(
        policy, service=service, workspace_id="ws_main", applied_by="operator:b", now=NOW
    )

    assert first.policy_version == 1
    assert second.policy_version == 2
    versions = list_policy_versions(service=service, workspace_id="ws_main")
    assert [(item.version, item.action, item.applied_by) for item in versions] == [
        (1, "apply", "operator:a"),
        (2, "apply", "operator:b"),
    ]
    assert get_sqlite_schema_versions(service.conn) == tuple(range(1, 15))


def test_policy_rollback_exactly_restores_versioned_authorization_state(
    tmp_path: Path,
) -> None:
    service = SQLiteV1Service(sqlite3.connect(":memory:"))
    settings = service.agent_enforcement_settings_repository
    settings.set_require_boundary(
        workspace_id="ws_main",
        agent_id="agent_exempt",
        require_boundary=False,
        now=NOW,
    )
    first_policy = _write_policy(
        tmp_path / "first.yaml",
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
""",
    )
    first = apply_policy_file(
        first_policy,
        service=service,
        workspace_id="ws_main",
        applied_by="operator:a",
        now=NOW,
    )

    second_policy = _write_policy(
        tmp_path / "second.yaml",
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
""",
    )
    apply_policy_file(
        second_policy,
        service=service,
        workspace_id="ws_main",
        applied_by="operator:b",
        now=NOW,
    )
    settings.set_require_subject_token(
        workspace_id="ws_main",
        agent_id="agent_subject_token",
        require_subject_token=True,
        now=NOW,
    )

    rolled_back = rollback_policy_version(
        service=service,
        workspace_id="ws_main",
        version=first.policy_version,
        applied_by="operator:rollback",
        now=NOW,
    )

    assert rolled_back.restored_version == 1
    assert rolled_back.policy_version == 3
    assert service.scope_bounds_repository.list_bounds_for_workspace("ws_main") == (
        ("agent_a", ("read:repo/a",)),
    )
    assert [
        rule.rule_id for rule in service.list_auto_approval_rules(workspace_id="ws_main")
    ] == ["apr_old"]
    assert settings.is_boundary_required(
        workspace_id="ws_main", agent_id="agent_other"
    ) is True
    assert settings.is_boundary_required(
        workspace_id="ws_main", agent_id="agent_exempt"
    ) is False
    assert settings.is_subject_token_required(
        workspace_id="ws_main", agent_id="agent_subject_token"
    ) is True
    assert settings.is_boundary_required(
        workspace_id="ws_main", agent_id="agent_subject_token"
    ) is True
    versions = list_policy_versions(service=service, workspace_id="ws_main")
    assert [(item.version, item.action, item.source_version) for item in versions] == [
        (1, "apply", None),
        (2, "apply", None),
        (3, "rollback", 1),
    ]


def test_policy_rollback_rejects_unknown_version_without_mutation() -> None:
    service = SQLiteV1Service(sqlite3.connect(":memory:"))
    with pytest.raises(ValueError, match="unknown policy version"):
        rollback_policy_version(
            service=service,
            workspace_id="ws_main",
            version=99,
            applied_by="operator:a",
            now=NOW,
        )
    assert list_policy_versions(service=service, workspace_id="ws_main") == ()


def test_policy_apply_rolls_back_every_write_when_a_late_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = SQLiteV1Service(sqlite3.connect(":memory:"))
    apply_policy_file(
        _write_policy(tmp_path / "first.yaml", FIRST_POLICY),
        service=service,
        workspace_id="ws_main",
        applied_by="operator:a",
        now=NOW,
    )
    before = _policy_state(service)

    # The boundary write is the LAST write step before the version record, so
    # by the time it raises the bounds and rules writes have already run.
    def boom(**_kwargs: object) -> None:
        raise RuntimeError("boundary write failed")

    monkeypatch.setattr(
        service.agent_enforcement_settings_repository, "set_require_boundary", boom
    )
    with pytest.raises(RuntimeError, match="boundary write failed"):
        apply_policy_file(
            _write_policy(tmp_path / "second.yaml", SECOND_POLICY),
            service=service,
            workspace_id="ws_main",
            applied_by="operator:b",
            now=NOW,
        )

    # All-or-nothing: the store is exactly as before the failed apply.
    assert _policy_state(service) == before
    assert service.scope_bounds_repository.get_bounds(
        workspace_id="ws_main", agent_id="agent_b"
    ) is None
    rule = service.auto_approval_rule_repository.get_rule("apr_old")
    assert rule is not None and rule.max_ttl_seconds == 300
    assert service.auto_approval_rule_repository.get_rule("apr_new") is None


def test_policy_apply_rolls_back_when_the_version_record_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = SQLiteV1Service(sqlite3.connect(":memory:"))
    apply_policy_file(
        _write_policy(tmp_path / "first.yaml", FIRST_POLICY),
        service=service,
        workspace_id="ws_main",
        applied_by="operator:a",
        now=NOW,
    )
    before = _policy_state(service)

    def boom(**_kwargs: object) -> int:
        raise RuntimeError("version record failed")

    monkeypatch.setattr("vinctor_service.policy_files._insert_policy_version", boom)
    with pytest.raises(RuntimeError, match="version record failed"):
        apply_policy_file(
            _write_policy(tmp_path / "second.yaml", SECOND_POLICY),
            service=service,
            workspace_id="ws_main",
            applied_by="operator:b",
            now=NOW,
        )

    # A policy state may never outlive its version record: everything unwinds.
    assert _policy_state(service) == before


def test_policy_apply_holds_one_write_transaction_for_the_whole_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    service = SQLiteV1Service(sqlite3.connect(str(db_path)))
    settings = service.agent_enforcement_settings_repository
    original = settings.set_require_boundary
    observed: dict[str, object] = {}

    def spy(**kwargs: object) -> None:
        observed["in_transaction"] = service.conn.in_transaction
        rival = sqlite3.connect(str(db_path), timeout=0.1)
        try:
            # BEGIN IMMEDIATE up front means a second writer cannot even START
            # while an apply is in flight: applies serialize, never interleave.
            try:
                rival.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as error:
                observed["rival_begin_error"] = str(error)
            else:
                observed["rival_begin_error"] = None
                rival.rollback()
            # And no reader observes the half-applied policy: the bounds write
            # that already ran inside this apply is invisible until commit.
            observed["rival_sees_bounds"] = rival.execute(
                "SELECT COUNT(*) FROM agent_issuable_scope_bounds"
                " WHERE workspace_id = 'ws_main'"
            ).fetchone()[0]
        finally:
            rival.close()
        original(**kwargs)

    monkeypatch.setattr(settings, "set_require_boundary", spy)
    result = apply_policy_file(
        _write_policy(tmp_path / "policy.yaml", FIRST_POLICY),
        service=service,
        workspace_id="ws_main",
        applied_by="operator:a",
        now=NOW,
    )

    assert observed["in_transaction"] is True
    assert "locked" in str(observed["rival_begin_error"])
    assert observed["rival_sees_bounds"] == 0
    assert result.policy_version == 1
    # After commit the write lock is released and the apply is fully visible.
    rival = sqlite3.connect(str(db_path), timeout=1.0)
    rival.execute("BEGIN IMMEDIATE")
    assert rival.execute(
        "SELECT COUNT(*) FROM agent_issuable_scope_bounds WHERE workspace_id = 'ws_main'"
    ).fetchone()[0] == 1
    rival.rollback()
    rival.close()


def test_policy_apply_snapshot_matches_live_policy_state(tmp_path: Path) -> None:
    service = SQLiteV1Service(sqlite3.connect(":memory:"))
    result = apply_policy_file(
        _write_policy(tmp_path / "policy.yaml", FIRST_POLICY),
        service=service,
        workspace_id="ws_main",
        applied_by="operator:a",
        now=NOW,
    )

    row = service.conn.execute(
        "SELECT snapshot_json FROM policy_versions WHERE workspace_id = ? AND version = ?",
        ("ws_main", result.policy_version),
    ).fetchone()
    assert json.loads(row[0]) == _snapshot_policy_state(service=service, workspace_id="ws_main")


def test_concurrent_policy_applies_serialize_without_torn_state(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    SQLiteV1Service(sqlite3.connect(str(db_path))).conn.close()

    # Both policies target the SAME agent and the SAME rule_id with different
    # content, so any interleaving of the two applies would show up as a mix.
    policy_a = _write_policy(
        tmp_path / "a.yaml",
        """
version: 1
workspace_id: ws_main
agent_bounds:
  - agent_id: agent_shared
    scopes: [read:repo/a]
auto_approval_rules:
  - rule_id: apr_shared
    name: shared
    target_agent_id: agent_shared
    allowed_scopes: [read:repo/a]
    max_ttl: 5m
""",
    )
    policy_b = _write_policy(
        tmp_path / "b.yaml",
        """
version: 1
workspace_id: ws_main
agent_bounds:
  - agent_id: agent_shared
    scopes: [write:repo/b]
auto_approval_rules:
  - rule_id: apr_shared
    name: shared
    target_agent_id: agent_shared
    allowed_scopes: [write:repo/b]
    max_ttl: 10m
""",
    )

    def apply_on_own_connection(path: Path, applied_by: str) -> None:
        conn = sqlite3.connect(str(db_path))
        try:
            worker = SQLiteV1Service(conn, initialize_schema=False)
            apply_policy_file(
                path, service=worker, workspace_id="ws_main", applied_by=applied_by, now=NOW
            )
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(apply_on_own_connection, policy_a, "operator:a"),
            pool.submit(apply_on_own_connection, policy_b, "operator:b"),
        ]
        for future in futures:
            future.result(timeout=30)

    service = SQLiteV1Service(sqlite3.connect(str(db_path)), initialize_schema=False)
    bounds = service.scope_bounds_repository.get_bounds(
        workspace_id="ws_main", agent_id="agent_shared"
    )
    rule = service.auto_approval_rule_repository.get_rule("apr_shared")
    assert rule is not None
    # The final state is ENTIRELY policy A or ENTIRELY policy B — never a mix.
    assert (bounds, rule.allowed_scopes, rule.max_ttl_seconds) in {
        (("read:repo/a",), ("read:repo/a",), 300),
        (("write:repo/b",), ("write:repo/b",), 600),
    }
    versions = list_policy_versions(service=service, workspace_id="ws_main")
    assert [(item.version, item.action) for item in versions] == [(1, "apply"), (2, "apply")]
    # The last recorded snapshot describes the live state exactly.
    row = service.conn.execute(
        "SELECT snapshot_json FROM policy_versions WHERE workspace_id = ? AND version = 2",
        ("ws_main",),
    ).fetchone()
    assert json.loads(row[0]) == _snapshot_policy_state(service=service, workspace_id="ws_main")
