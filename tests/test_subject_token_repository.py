import sqlite3
from datetime import UTC, datetime, timedelta

from vinctor_service import (
    InMemorySubjectTokenRepository,
    SQLiteSubjectTokenRepository,
    SubjectToken,
)
from vinctor_service.sqlite import get_sqlite_schema_versions, init_sqlite_schema

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _token(token_hash: str = "hash_main") -> SubjectToken:
    return SubjectToken(
        token_id="vtk_main",
        token_hash=token_hash,
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        audience="pep_git_host",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=300),
        created_by="agent_release",
    )


def test_in_memory_insert_and_get_by_hash() -> None:
    repo = InMemorySubjectTokenRepository()
    repo.insert(_token())
    assert repo.get_by_hash("hash_main") == _token()
    assert repo.get_by_hash("missing") is None


def test_sqlite_insert_and_get_by_hash_round_trip(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = SQLiteSubjectTokenRepository(conn)
    repo.insert(_token())
    assert repo.get_by_hash("hash_main") == _token()
    assert repo.get_by_hash("missing") is None


def test_sqlite_schema_records_version_3(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    assert get_sqlite_schema_versions(conn) == (1, 2, 3)
