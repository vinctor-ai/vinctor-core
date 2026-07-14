import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vinctor_service.policy_files import (
    apply_policy_file,
    list_policy_versions,
    rollback_policy_version,
)
from vinctor_service.sqlite import SQLiteV1Service, get_sqlite_schema_versions

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)


def _write_policy(path: Path, body: str) -> Path:
    path.write_text(body.strip(), encoding="utf-8")
    return path


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
    assert get_sqlite_schema_versions(service.conn) == tuple(range(1, 14))


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
