import sqlite3
from datetime import UTC, datetime, timedelta

from vinctor_service import (
    InMemorySubjectTokenRepository,
    SQLiteSubjectTokenRepository,
    SubjectToken,
)
from vinctor_service.sqlite import get_sqlite_schema_versions, init_sqlite_schema

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _token(
    token_hash: str = "hash_main",
    *,
    revoked_at: datetime | None = None,
    bound_action: str | None = None,
    bound_resource: str | None = None,
    pop_secret: str | None = None,
) -> SubjectToken:
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
        revoked_at=revoked_at,
        bound_action=bound_action,
        bound_resource=bound_resource,
        pop_secret=pop_secret,
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


def test_sqlite_schema_records_version_7(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    assert get_sqlite_schema_versions(conn) == tuple(range(1, 13))


def test_in_memory_round_trip_revoked_at() -> None:
    repo = InMemorySubjectTokenRepository()
    revoked = _token(revoked_at=NOW + timedelta(seconds=60))
    repo.insert(revoked)
    stored = repo.get_by_hash("hash_main")
    assert stored is not None
    assert stored.revoked_at == NOW + timedelta(seconds=60)


def test_sqlite_round_trip_revoked_at(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = SQLiteSubjectTokenRepository(conn)
    revoked = _token(revoked_at=NOW + timedelta(seconds=60))
    repo.insert(revoked)
    stored = repo.get_by_hash("hash_main")
    assert stored is not None
    assert stored.revoked_at == NOW + timedelta(seconds=60)


def test_in_memory_round_trip_bound_action_resource() -> None:
    repo = InMemorySubjectTokenRepository()
    bound = _token(bound_action="write", bound_resource="repo/x/y")
    repo.insert(bound)
    stored = repo.get_by_hash("hash_main")
    assert stored is not None
    assert stored.bound_action == "write"
    assert stored.bound_resource == "repo/x/y"


def test_in_memory_round_trip_unbound_defaults_none() -> None:
    repo = InMemorySubjectTokenRepository()
    repo.insert(_token())
    stored = repo.get_by_hash("hash_main")
    assert stored is not None
    assert stored.bound_action is None
    assert stored.bound_resource is None


def test_sqlite_round_trip_bound_action_resource(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = SQLiteSubjectTokenRepository(conn)
    bound = _token(bound_action="write", bound_resource="repo/x/y")
    repo.insert(bound)
    stored = repo.get_by_hash("hash_main")
    assert stored is not None
    assert stored.bound_action == "write"
    assert stored.bound_resource == "repo/x/y"


def test_sqlite_round_trip_unbound_defaults_none(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = SQLiteSubjectTokenRepository(conn)
    repo.insert(_token())
    stored = repo.get_by_hash("hash_main")
    assert stored is not None
    assert stored.bound_action is None
    assert stored.bound_resource is None


def test_in_memory_round_trip_pop_secret() -> None:
    repo = InMemorySubjectTokenRepository()
    repo.insert(_token(pop_secret="pop-secret-value"))
    stored = repo.get_by_hash("hash_main")
    assert stored is not None
    assert stored.pop_secret == "pop-secret-value"


def test_in_memory_round_trip_pop_secret_defaults_none() -> None:
    repo = InMemorySubjectTokenRepository()
    repo.insert(_token())
    stored = repo.get_by_hash("hash_main")
    assert stored is not None
    assert stored.pop_secret is None


def test_sqlite_round_trip_pop_secret(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = SQLiteSubjectTokenRepository(conn)
    repo.insert(_token(pop_secret="pop-secret-value"))
    stored = repo.get_by_hash("hash_main")
    assert stored is not None
    assert stored.pop_secret == "pop-secret-value"


def test_sqlite_round_trip_pop_secret_defaults_none(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = SQLiteSubjectTokenRepository(conn)
    repo.insert(_token())
    stored = repo.get_by_hash("hash_main")
    assert stored is not None
    assert stored.pop_secret is None
