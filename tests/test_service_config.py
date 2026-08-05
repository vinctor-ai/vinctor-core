from __future__ import annotations

from pathlib import Path

import pytest

from vinctor_service.service_config import (
    DEFAULT_POP_REPLAY_MAX_ENTRIES,
    DEFAULT_POP_REPLAY_MAX_PER_TOKEN,
    DEFAULT_SERVICE_DB_PATH,
    KEY_STORAGE_MODE,
    ServiceRuntimeConfig,
    load_pop_replay_caps,
    load_service_runtime_config,
)


def test_service_runtime_config_defaults() -> None:
    config = load_service_runtime_config(env={})

    assert config == ServiceRuntimeConfig(
        host="127.0.0.1",
        port=8765,
        sqlite_db_path=DEFAULT_SERVICE_DB_PATH,
        log_level="info",
        service_mode="local",
        key_storage_mode=KEY_STORAGE_MODE,
        storage_backend="sqlite",
        postgres_dsn=None,
    )


def test_service_runtime_config_reads_environment(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"

    config = load_service_runtime_config(
        env={
            "VINCTOR_HOST": "0.0.0.0",
            "VINCTOR_PORT": "9999",
            "VINCTOR_DB": str(db_path),
            "VINCTOR_LOG_LEVEL": "DEBUG",
            "VINCTOR_SERVICE_MODE": "SELF_HOSTED",
        }
    )

    assert config.host == "0.0.0.0"
    assert config.port == 9999
    assert config.sqlite_db_path == db_path
    assert config.log_level == "debug"
    assert config.service_mode == "self_hosted"


def test_service_runtime_config_selects_postgres_from_environment() -> None:
    config = load_service_runtime_config(
        env={
            "VINCTOR_STORAGE_BACKEND": "postgres",
            "VINCTOR_POSTGRES_DSN": "postgresql://vinctor@db/vinctor",
        }
    )

    assert config.storage_backend == "postgres"
    assert config.postgres_dsn == "postgresql://vinctor@db/vinctor"


def test_service_runtime_config_requires_dsn_for_postgres() -> None:
    with pytest.raises(ValueError, match="VINCTOR_POSTGRES_DSN"):
        load_service_runtime_config(env={"VINCTOR_STORAGE_BACKEND": "postgres"})


def test_service_runtime_config_repr_does_not_expose_postgres_dsn() -> None:
    config = ServiceRuntimeConfig(
        storage_backend="postgres",
        postgres_dsn="postgresql://vinctor:secret@db/vinctor",
    )

    assert "secret" not in repr(config)


def test_service_runtime_config_cli_values_override_environment(tmp_path: Path) -> None:
    env_db = tmp_path / "env.sqlite"
    cli_db = tmp_path / "cli.sqlite"

    config = load_service_runtime_config(
        host="127.0.0.2",
        port=0,
        sqlite_db_path=cli_db,
        log_level="warning",
        service_mode="local",
        env={
            "VINCTOR_HOST": "0.0.0.0",
            "VINCTOR_PORT": "9999",
            "VINCTOR_DB": str(env_db),
            "VINCTOR_LOG_LEVEL": "debug",
            "VINCTOR_SERVICE_MODE": "self_hosted",
        },
    )

    assert config.host == "127.0.0.2"
    assert config.port == 0
    assert config.sqlite_db_path == cli_db
    assert config.log_level == "warning"
    assert config.service_mode == "local"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"port": 70000}, "port must be between"),
        ({"service_mode": "hosted"}, "service_mode must be one of"),
        ({"log_level": "verbose"}, "log_level must be one of"),
        ({"storage_backend": "mysql"}, "storage_backend must be one of"),
    ],
)
def test_service_runtime_config_rejects_invalid_values(
    kwargs: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ServiceRuntimeConfig(**kwargs)


def test_pop_replay_caps_defaults() -> None:
    assert load_pop_replay_caps(env={}) == (
        DEFAULT_POP_REPLAY_MAX_ENTRIES,
        DEFAULT_POP_REPLAY_MAX_PER_TOKEN,
    )
    assert load_pop_replay_caps(env={}) == (10000, 256)


def test_pop_replay_caps_read_environment() -> None:
    assert load_pop_replay_caps(
        env={
            "VINCTOR_POP_REPLAY_MAX_ENTRIES": "50000",
            "VINCTOR_POP_REPLAY_MAX_PER_TOKEN": "1024",
        }
    ) == (50000, 1024)


def test_pop_replay_caps_reject_invalid_values() -> None:
    with pytest.raises(ValueError, match="VINCTOR_POP_REPLAY_MAX_ENTRIES"):
        load_pop_replay_caps(env={"VINCTOR_POP_REPLAY_MAX_ENTRIES": "many"})
    with pytest.raises(ValueError, match="VINCTOR_POP_REPLAY_MAX_PER_TOKEN"):
        load_pop_replay_caps(env={"VINCTOR_POP_REPLAY_MAX_PER_TOKEN": "0"})
    with pytest.raises(ValueError, match="VINCTOR_POP_REPLAY_MAX_ENTRIES"):
        load_pop_replay_caps(env={"VINCTOR_POP_REPLAY_MAX_ENTRIES": "-5"})
