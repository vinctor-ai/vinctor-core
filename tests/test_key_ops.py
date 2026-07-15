from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vinctor_service.key_ops import (
    rotate_agent_key,
    rotate_pep_key,
    rotate_workspace_key,
    serialize_key_record,
)
from vinctor_service.keys import (
    AGENT_KEY_PREFIX,
    PEP_KEY_PREFIX,
    WORKSPACE_KEY_PREFIX,
    SQLiteLocalKeyRepository,
)
from vinctor_service.sqlite import SQLiteV1Service

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _repo(db_path: Path) -> SQLiteLocalKeyRepository:
    conn = sqlite3.connect(db_path)
    SQLiteV1Service(conn)
    return SQLiteLocalKeyRepository(conn)


def test_serialize_key_record_omits_hash(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "vinctor.sqlite")
    created = repo.create_workspace_key(workspace_id="ws_demo", now=NOW)

    body = serialize_key_record(created.record)

    assert body["key_id"] == created.record.key_id
    assert body["key_type"] == "workspace"
    assert body["status"] == "active"
    assert body["workspace_id"] == "ws_demo"
    assert "key_hash" not in body
    assert created.raw_key not in body.values()


def test_rotate_workspace_key_mints_new_and_revokes_old(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "vinctor.sqlite")
    old = repo.create_workspace_key(workspace_id="ws_demo", now=NOW)

    result = rotate_workspace_key(repo, workspace_id="ws_demo", now=NOW)

    assert result.raw_key.startswith(WORKSPACE_KEY_PREFIX)
    assert result.new_key_id != old.record.key_id
    assert old.record.key_id in result.revoked_key_ids
    assert repo.get_by_id(old.record.key_id).status == "revoked"
    assert repo.get_by_id(result.new_key_id).status == "active"


def test_rotate_agent_key_only_revokes_same_agent(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "vinctor.sqlite")
    agent_old = repo.create_agent_key(workspace_id="ws_demo", agent_id="agent_a", now=NOW)
    other_agent = repo.create_agent_key(workspace_id="ws_demo", agent_id="agent_b", now=NOW)
    workspace_key = repo.create_workspace_key(workspace_id="ws_demo", now=NOW)

    result = rotate_agent_key(repo, workspace_id="ws_demo", agent_id="agent_a", now=NOW)

    assert result.raw_key.startswith(AGENT_KEY_PREFIX)
    assert agent_old.record.key_id in result.revoked_key_ids
    assert repo.get_by_id(agent_old.record.key_id).status == "revoked"
    assert repo.get_by_id(other_agent.record.key_id).status == "active"
    assert repo.get_by_id(workspace_key.record.key_id).status == "active"


def test_rotate_workspace_key_does_not_revoke_agent_keys(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "vinctor.sqlite")
    agent_key = repo.create_agent_key(workspace_id="ws_demo", agent_id="agent_a", now=NOW)

    rotate_workspace_key(repo, workspace_id="ws_demo", now=NOW)

    assert repo.get_by_id(agent_key.record.key_id).status == "active"


def test_rotate_pep_key_only_revokes_same_pep(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "vinctor.sqlite")
    pep_old = repo.create_pep_key(workspace_id="ws_demo", pep_id="pep_a", now=NOW)
    other_pep = repo.create_pep_key(workspace_id="ws_demo", pep_id="pep_b", now=NOW)
    agent_key = repo.create_agent_key(workspace_id="ws_demo", agent_id="agent_a", now=NOW)

    result = rotate_pep_key(repo, workspace_id="ws_demo", pep_id="pep_a", now=NOW)

    assert result.raw_key.startswith(PEP_KEY_PREFIX)
    assert pep_old.record.key_id in result.revoked_key_ids
    assert repo.get_by_id(pep_old.record.key_id).status == "revoked"
    assert repo.get_by_id(other_pep.record.key_id).status == "active"
    assert repo.get_by_id(agent_key.record.key_id).status == "active"


def test_rotate_rejects_running_inside_an_open_transaction(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "vinctor.sqlite")
    old = repo.create_workspace_key(workspace_id="ws_demo", now=NOW)

    # A caller that already holds a transaction must not be able to nest a
    # rotation into it: nesting would return the plaintext before the caller's
    # commit and drop the key on rollback. Rotation owns its transaction.
    repo._conn.execute("BEGIN")
    try:
        with pytest.raises(RuntimeError, match="cannot run inside an open transaction"):
            rotate_workspace_key(repo, workspace_id="ws_demo", now=NOW)
    finally:
        repo._conn.rollback()

    # The predecessor is untouched and still the only active workspace key.
    assert repo.get_by_id(old.record.key_id).status == "active"


def test_rotate_is_atomic_when_revocation_fails(
    tmp_path: Path, monkeypatch
) -> None:
    repo = _repo(tmp_path / "vinctor.sqlite")
    old = repo.create_workspace_key(workspace_id="ws_demo", now=NOW)

    # Fail during the revoke step, after the new key has been minted. Without one
    # transaction the freshly minted key is already committed — leaving two active
    # workspace keys and a returned plaintext for a rotation that did not finish.
    def _boom(*_args, **_kwargs):
        raise RuntimeError("revoke failed mid-rotation")

    monkeypatch.setattr(repo, "revoke_key", _boom)

    with pytest.raises(RuntimeError, match="revoke failed"):
        rotate_workspace_key(repo, workspace_id="ws_demo", now=NOW)

    # All-or-nothing: the predecessor is still the sole active workspace key, and
    # no half-minted key leaked (the plaintext was never returned to the caller).
    active_workspace = [
        record
        for record in repo.list_for_workspace("ws_demo")
        if record.status == "active" and record.key_type == "workspace"
    ]
    assert [record.key_id for record in active_workspace] == [old.record.key_id]
