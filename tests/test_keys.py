from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vinctor_service.keys import (
    AGENT_KEY_PREFIX,
    WORKSPACE_KEY_PREFIX,
    SQLiteLocalKeyRepository,
    mask_key,
)
from vinctor_service.sqlite import init_sqlite_schema

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def connect_db(tmp_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_path / "vinctor.sqlite")
    init_sqlite_schema(conn)
    return conn


def test_local_key_repository_creates_hashed_workspace_key(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    repository = SQLiteLocalKeyRepository(conn)

    created = repository.create_workspace_key(
        workspace_id="ws_main",
        raw_key="wsk_test_secret",
        now=NOW,
        key_id="lkey_workspace",
    )

    row = conn.execute(
        "SELECT key_type, workspace_id, agent_id, key_hash, key_prefix, status FROM local_keys"
    ).fetchone()
    assert created.raw_key == "wsk_test_secret"
    assert created.record.key_id == "lkey_workspace"
    assert row[0:3] == ("workspace", "ws_main", None)
    assert row[3] != "wsk_test_secret"
    assert row[4:6] == (WORKSPACE_KEY_PREFIX, "active")
    conn.close()


def test_local_key_repository_resolves_agent_identity_and_tracks_usage(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    repository = SQLiteLocalKeyRepository(conn)
    repository.create_agent_key(
        workspace_id="ws_main",
        agent_id="agent_release",
        raw_key="aak_test_secret",
        now=NOW,
        key_id="lkey_agent",
    )

    identity = repository.resolve_agent_identity(
        "aak_test_secret",
        now=NOW + timedelta(seconds=1),
    )
    record = repository.get_by_id("lkey_agent")

    assert identity is not None
    assert identity.workspace_id == "ws_main"
    assert identity.agent_id == "agent_release"
    assert record is not None
    assert record.last_used_at == NOW + timedelta(seconds=1)
    conn.close()


def test_local_key_repository_does_not_cross_key_types(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    repository = SQLiteLocalKeyRepository(conn)
    repository.create_workspace_key(
        workspace_id="ws_main",
        raw_key="wsk_test_secret",
        now=NOW,
    )
    repository.create_agent_key(
        workspace_id="ws_main",
        agent_id="agent_release",
        raw_key="aak_test_secret",
        now=NOW,
    )

    assert repository.resolve_agent_identity("wsk_test_secret", now=NOW) is None
    assert repository.resolve_workspace_identity("aak_test_secret", now=NOW) is None
    conn.close()


def test_local_key_repository_revokes_key(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    repository = SQLiteLocalKeyRepository(conn)
    created = repository.create_agent_key(
        workspace_id="ws_main",
        agent_id="agent_release",
        raw_key="aak_test_secret",
        now=NOW,
    )

    revoked = repository.revoke_key(
        created.record.key_id,
        now=NOW + timedelta(seconds=1),
    )

    assert revoked is not None
    assert revoked.status == "revoked"
    assert revoked.revoked_at == NOW + timedelta(seconds=1)
    assert repository.resolve_agent_identity("aak_test_secret", now=NOW) is None
    conn.close()


def test_local_key_repository_rejects_invalid_prefixes(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    repository = SQLiteLocalKeyRepository(conn)

    with pytest.raises(ValueError, match=f"key must start with {WORKSPACE_KEY_PREFIX}"):
        repository.create_workspace_key(
            workspace_id="ws_main",
            raw_key="aak_wrong_type",
            now=NOW,
        )

    with pytest.raises(ValueError, match=f"key must start with {AGENT_KEY_PREFIX}"):
        repository.create_agent_key(
            workspace_id="ws_main",
            agent_id="agent_release",
            raw_key="agk_old_prefix",
            now=NOW,
        )
    conn.close()


def test_local_key_repository_ensure_reuses_active_key(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    repository = SQLiteLocalKeyRepository(conn)

    first = repository.ensure_agent_key(
        workspace_id="ws_main",
        agent_id="agent_release",
        raw_key="aak_test_secret",
        now=NOW,
    )
    second = repository.ensure_agent_key(
        workspace_id="ws_main",
        agent_id="agent_release",
        raw_key="aak_test_secret",
        now=NOW,
    )

    assert first == second
    assert len(repository.list_for_workspace("ws_main")) == 1
    conn.close()


def test_mask_key_preserves_prefix_and_suffix() -> None:
    assert mask_key("aak_abcdefghijklmnopqrstuvwxyz") == "aak_abcd...wxyz"
