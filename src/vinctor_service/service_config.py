from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from vinctor_service.oidc import OidcConfig, load_oidc_config

DEFAULT_SERVICE_DB_PATH = Path(".vinctor/vinctor.sqlite")
DEFAULT_POP_REPLAY_MAX_ENTRIES = 10000
DEFAULT_POP_REPLAY_MAX_PER_TOKEN = 256
DEFAULT_SUBJECT_TOKEN_TTL_SECONDS = 300
DEFAULT_SUBJECT_TOKEN_MAX_TTL_SECONDS = 3600
DEFAULT_SUBJECT_TOKEN_POP_SKEW_SECONDS = 30
SERVICE_MODES = ("local", "self_hosted")
LOG_LEVELS = ("debug", "info", "warning", "error")
KEY_STORAGE_MODE = "sqlite_hashes"
STORAGE_BACKENDS = ("sqlite", "postgres")


@dataclass(frozen=True)
class ServiceRuntimeConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    sqlite_db_path: Path = DEFAULT_SERVICE_DB_PATH
    log_level: str = "info"
    service_mode: str = "local"
    key_storage_mode: str = KEY_STORAGE_MODE
    metrics: bool = False
    access_log: bool = False
    storage_backend: str = "sqlite"
    postgres_dsn: str | None = field(default=None, repr=False)
    oidc: OidcConfig | None = None

    def __post_init__(self) -> None:
        if not self.host:
            raise ValueError("host is required")
        if self.port < 0 or self.port > 65535:
            raise ValueError("port must be between 0 and 65535")
        if self.service_mode not in SERVICE_MODES:
            raise ValueError(f"service_mode must be one of: {', '.join(SERVICE_MODES)}")
        if self.log_level not in LOG_LEVELS:
            raise ValueError(f"log_level must be one of: {', '.join(LOG_LEVELS)}")
        if self.key_storage_mode != KEY_STORAGE_MODE:
            raise ValueError(f"key_storage_mode must be {KEY_STORAGE_MODE}")
        if self.storage_backend not in STORAGE_BACKENDS:
            raise ValueError(
                f"storage_backend must be one of: {', '.join(STORAGE_BACKENDS)}"
            )
        if self.storage_backend == "postgres" and not self.postgres_dsn:
            raise ValueError(
                "VINCTOR_POSTGRES_DSN is required when storage_backend is postgres"
            )


def load_service_runtime_config(
    *,
    host: str | None = None,
    port: int | str | None = None,
    sqlite_db_path: str | Path | None = None,
    log_level: str | None = None,
    service_mode: str | None = None,
    metrics: bool | None = None,
    access_log: bool | None = None,
    storage_backend: str | None = None,
    postgres_dsn: str | None = None,
    env: Mapping[str, str] | None = None,
) -> ServiceRuntimeConfig:
    values = env or {}
    resolved_host = host or values.get("VINCTOR_HOST") or "127.0.0.1"
    resolved_port = _parse_port(port if port is not None else values.get("VINCTOR_PORT", 8765))
    resolved_db_path = Path(sqlite_db_path or values.get("VINCTOR_DB") or DEFAULT_SERVICE_DB_PATH)
    resolved_log_level = (log_level or values.get("VINCTOR_LOG_LEVEL") or "info").lower()
    resolved_service_mode = (
        service_mode or values.get("VINCTOR_SERVICE_MODE") or "local"
    ).lower()
    resolved_metrics = (
        metrics
        if metrics is not None
        else _parse_bool(values.get("VINCTOR_METRICS"))
    )
    resolved_access_log = (
        access_log
        if access_log is not None
        else _parse_bool(values.get("VINCTOR_ACCESS_LOG"))
    )
    resolved_storage_backend = (
        storage_backend or values.get("VINCTOR_STORAGE_BACKEND") or "sqlite"
    ).lower()
    resolved_postgres_dsn = postgres_dsn or values.get("VINCTOR_POSTGRES_DSN")
    return ServiceRuntimeConfig(
        host=resolved_host,
        port=resolved_port,
        sqlite_db_path=resolved_db_path.expanduser(),
        log_level=resolved_log_level,
        service_mode=resolved_service_mode,
        metrics=resolved_metrics,
        access_log=resolved_access_log,
        storage_backend=resolved_storage_backend,
        postgres_dsn=resolved_postgres_dsn,
        oidc=load_oidc_config(values),
    )


def load_pop_replay_caps(env: Mapping[str, str] | None = None) -> tuple[int, int]:
    """Resolve the PoP replay-cache caps ``(max_entries, max_per_token)``.

    Reads ``VINCTOR_POP_REPLAY_MAX_ENTRIES`` and
    ``VINCTOR_POP_REPLAY_MAX_PER_TOKEN`` (defaulting to ``os.environ``), so a
    high-throughput deployment can raise the fail-closed caps without a code
    change. Invalid values raise instead of silently falling back: a typo must
    not quietly restore a cap the operator meant to raise.
    """
    values = os.environ if env is None else env
    return (
        _parse_cap(values.get("VINCTOR_POP_REPLAY_MAX_ENTRIES"),
                   DEFAULT_POP_REPLAY_MAX_ENTRIES, "VINCTOR_POP_REPLAY_MAX_ENTRIES"),
        _parse_cap(values.get("VINCTOR_POP_REPLAY_MAX_PER_TOKEN"),
                   DEFAULT_POP_REPLAY_MAX_PER_TOKEN, "VINCTOR_POP_REPLAY_MAX_PER_TOKEN"),
    )


def _parse_cap(value: str | None, default: int, name: str) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a positive integer") from error
    if parsed < 1:
        raise ValueError(f"{name} must be a positive integer")
    return parsed


def _parse_port(value: int | str) -> int:
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except ValueError as error:
        raise ValueError("port must be an integer") from error


def _parse_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in ("1", "true")
