from __future__ import annotations

import base64
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime
from functools import partial

import pytest

from vinctor_service.idempotency_keyring import IdempotencyKeyring
from vinctor_service.service_config import load_service_runtime_config

KEYRING_ENV = "VINCTOR_IDEMPOTENCY_KEYRING_JSON"
ACTIVE_ENV = "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION"


class _ReadyResult:
    def fetchone(self) -> tuple[int]:
        return (1,)


class _FakePostgresConnection:
    def __init__(self) -> None:
        self.validator_calls: list[tuple[str, Callable[[object], None]]] = []

    def add_replacement_validator(self, validator: Callable[[object], None]) -> None:
        self.validator_calls.append(("replacement", validator))

    def add_readiness_validator(self, validator: Callable[[object], None]) -> None:
        self.validator_calls.append(("readiness", validator))

    @contextmanager
    def transaction(self) -> Iterator[None]:
        yield

    def execute(self, query: str) -> _ReadyResult:
        assert query == "SELECT 1"
        return _ReadyResult()

    def close(self) -> None:
        pass


class _FakePostgresService:
    def __init__(self, keyring: IdempotencyKeyring | None) -> None:
        self.idempotency_keyring = keyring

    def close(self) -> None:
        pass


class _FakePostgresKeyRepository:
    def resolve_identity(self, _raw_key: str, _used_at: datetime | None = None) -> None:
        return None

    resolve_agent_identity = resolve_identity
    resolve_workspace_identity = resolve_identity
    resolve_auditor_identity = resolve_identity
    resolve_service_operator = resolve_identity
    resolve_pep_identity = resolve_identity


class _FakeServer:
    server_address = ("127.0.0.1", 0)

    def server_close(self) -> None:
        pass


class _PostgresServiceFactorySpy:
    def __init__(self) -> None:
        self.calls: list[dict[str, IdempotencyKeyring]] = []

    def __call__(
        self,
        _connection: _FakePostgresConnection,
        **kwargs: IdempotencyKeyring,
    ) -> _FakePostgresService:
        self.calls.append(kwargs)
        return _FakePostgresService(kwargs.get("idempotency_keyring"))


def _postgres_env(*, keyed: bool) -> Mapping[str, str]:
    env = {
        "VINCTOR_STORAGE_BACKEND": "postgres",
        "VINCTOR_POSTGRES_DSN": "postgresql://vinctor@db/vinctor",
    }
    if keyed:
        encoded = base64.b64encode(b"k" * 32).decode("ascii")
        env.update(
            {
                KEYRING_ENV: f'{{"primary":"{encoded}"}}',
                ACTIVE_ENV: "primary",
            }
        )
    return env


def _assert_exact_factory_call(
    spy: _PostgresServiceFactorySpy,
    keyring: IdempotencyKeyring | None,
) -> None:
    assert len(spy.calls) == 1
    if keyring is None:
        assert spy.calls == [{}]
        return
    assert tuple(spy.calls[0]) == ("idempotency_keyring",)
    assert spy.calls[0]["idempotency_keyring"] is keyring


def _assert_exact_validator_registration(
    connection: _FakePostgresConnection,
    keyring: IdempotencyKeyring | None,
) -> None:
    from vinctor_service.idempotency_readiness import (
        require_postgres_idempotency_compatible,
        require_postgres_idempotency_ready,
    )

    assert [kind for kind, _validator in connection.validator_calls] == [
        "replacement",
        "readiness",
    ]
    for (_kind, validator), expected in zip(
        connection.validator_calls,
        (
            require_postgres_idempotency_compatible,
            require_postgres_idempotency_ready,
        ),
        strict=True,
    ):
        assert isinstance(validator, partial)
        assert validator.func is expected
        assert validator.args == ()
        assert validator.keywords == {"keyring": keyring}


@pytest.mark.parametrize("keyed", (False, True), ids=("absent", "keyed"))
def test_service_runtime_postgres_factory_preserves_absent_call_and_keyed_identity(
    monkeypatch: pytest.MonkeyPatch,
    *,
    keyed: bool,
) -> None:
    # Given a PostgreSQL runtime factory spy and one boundary-parsed configuration.
    from vinctor_service import service_runtime

    connection = _FakePostgresConnection()
    factory = _PostgresServiceFactorySpy()
    monkeypatch.setattr(service_runtime, "connect_postgres", lambda _dsn: connection)
    monkeypatch.setattr(service_runtime, "PostgresV1Service", factory)
    monkeypatch.setattr(
        service_runtime,
        "PostgresLocalKeyRepository",
        lambda _connection: _FakePostgresKeyRepository(),
    )
    monkeypatch.setattr(
        service_runtime,
        "create_v1_http_server",
        lambda *_args, **_kwargs: _FakeServer(),
    )
    config = load_service_runtime_config(env=_postgres_env(keyed=keyed))

    # When the service runtime constructs its PostgreSQL service.
    handle = service_runtime.prepare_service_runtime(config)

    # Then absent config uses no keyword and keyed config injects the same instance.
    try:
        _assert_exact_factory_call(factory, config.idempotency_keyring)
        _assert_exact_validator_registration(connection, config.idempotency_keyring)
    finally:
        handle.close()


@pytest.mark.parametrize("keyed", (False, True), ids=("absent", "keyed"))
def test_storage_runtime_postgres_factory_preserves_absent_call_and_keyed_identity(
    monkeypatch: pytest.MonkeyPatch,
    *,
    keyed: bool,
) -> None:
    # Given a PostgreSQL storage factory spy and one boundary-parsed configuration.
    from vinctor_service import storage_runtime

    connection = _FakePostgresConnection()
    factory = _PostgresServiceFactorySpy()
    monkeypatch.setattr(storage_runtime, "connect_postgres", lambda _dsn: connection)
    monkeypatch.setattr(storage_runtime, "PostgresV1Service", factory)
    monkeypatch.setattr(storage_runtime, "postgres_idempotency_ready", lambda *_args: True)
    config = load_service_runtime_config(env=_postgres_env(keyed=keyed))

    # When the decision-storage runtime constructs its PostgreSQL service.
    handle = storage_runtime.prepare_decision_storage(config)

    # Then absent config uses no keyword and keyed config injects the same instance.
    try:
        _assert_exact_factory_call(factory, config.idempotency_keyring)
        _assert_exact_validator_registration(connection, config.idempotency_keyring)
    finally:
        handle.close()
