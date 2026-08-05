from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from traceback import format_exception

import pytest

from vinctor_service.audit_anchor import (
    AuditAnchor,
    NullAnchor,
    StdoutAnchor,
    anchor_from_env,
)
from vinctor_service.audit_export import (
    AuditExport,
    NullExport,
    OtlpHttpExport,
    StdoutExport,
    audit_export_from_env,
)
from vinctor_service.audit_sink import audit_sinks_from_env
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import connect_sqlite

SinkFactory = Callable[[dict[str, str]], AuditAnchor | AuditExport]


@pytest.mark.parametrize(
    ("variable", "factory"),
    [
        ("VINCTOR_AUDIT_ANCHOR", anchor_from_env),
        ("VINCTOR_AUDIT_EXPORT", audit_export_from_env),
    ],
)
def test_explicit_unknown_audit_sink_rejects_startup(
    variable: str,
    factory: SinkFactory,
) -> None:
    # Given
    secret = "SUPERSECRET"
    env = {variable: f"bad://{secret}/path?token=top-secret"}

    # When
    with pytest.raises(ValueError, match=variable) as exc_info:
        factory(env)

    # Then
    assert secret not in str(exc_info.value)
    assert "top-secret" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("variable", "factory"),
    [
        ("VINCTOR_AUDIT_ANCHOR", anchor_from_env),
        ("VINCTOR_AUDIT_EXPORT", audit_export_from_env),
    ],
)
def test_empty_file_audit_sink_path_rejects_startup(
    variable: str,
    factory: SinkFactory,
) -> None:
    # Given
    env = {variable: "file:"}

    # When / Then
    with pytest.raises(ValueError, match=variable):
        factory(env)


@pytest.mark.parametrize(
    ("variable", "factory"),
    [
        ("VINCTOR_AUDIT_ANCHOR", anchor_from_env),
        ("VINCTOR_AUDIT_EXPORT", audit_export_from_env),
    ],
)
def test_unopenable_file_audit_sink_destination_rejects_startup(
    tmp_path: Path,
    variable: str,
    factory: SinkFactory,
) -> None:
    # Given: a directory cannot be opened as an append-only file destination.
    secret = "SUPERSECRET"
    destination = tmp_path / secret
    destination.mkdir()
    env = {variable: f"file:{destination}"}

    # When
    with pytest.raises(ValueError, match=variable) as exc_info:
        factory(env)

    # Then
    rendered = "".join(format_exception(exc_info.value))
    assert secret not in rendered
    assert str(destination) not in rendered


@pytest.mark.parametrize(
    ("variable", "factory"),
    [
        ("VINCTOR_AUDIT_ANCHOR", anchor_from_env),
        ("VINCTOR_AUDIT_EXPORT", audit_export_from_env),
    ],
)
def test_file_audit_sink_is_opened_at_startup_without_audit_content(
    tmp_path: Path,
    variable: str,
    factory: SinkFactory,
) -> None:
    # Given
    destination = tmp_path / "audit.jsonl"

    # When
    factory({variable: f"file:{destination}"})

    # Then
    assert destination.read_bytes() == b""


def test_sqlite_startup_rejects_unknown_sink_even_when_other_sink_is_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.setenv("VINCTOR_AUDIT_ANCHOR", "stdout")
    monkeypatch.setenv("VINCTOR_AUDIT_EXPORT", "unknown:sink")
    conn = connect_sqlite(":memory:")

    # When / Then
    try:
        with pytest.raises(ValueError, match="VINCTOR_AUDIT_EXPORT"):
            SQLiteV1Service(conn)
    finally:
        conn.close()


def test_invalid_anchor_rejects_startup_even_when_export_is_valid() -> None:
    # Given
    env = {
        "VINCTOR_AUDIT_ANCHOR": "unknown:sink",
        "VINCTOR_AUDIT_EXPORT": "stdout",
    }

    # When / Then
    with pytest.raises(ValueError, match="VINCTOR_AUDIT_ANCHOR"):
        audit_sinks_from_env(env)


def test_sqlite_startup_rejects_empty_file_sink_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.delenv("VINCTOR_AUDIT_ANCHOR", raising=False)
    monkeypatch.setenv("VINCTOR_AUDIT_EXPORT", "file:")
    conn = connect_sqlite(":memory:")

    # When / Then
    try:
        with pytest.raises(ValueError, match="VINCTOR_AUDIT_EXPORT"):
            SQLiteV1Service(conn)
    finally:
        conn.close()


def test_sqlite_startup_rejects_unopenable_file_sink_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.setenv("VINCTOR_AUDIT_ANCHOR", f"file:{tmp_path}")
    monkeypatch.delenv("VINCTOR_AUDIT_EXPORT", raising=False)
    conn = connect_sqlite(":memory:")

    # When / Then
    try:
        with pytest.raises(ValueError, match="VINCTOR_AUDIT_ANCHOR"):
            SQLiteV1Service(conn)
    finally:
        conn.close()


def test_sqlite_required_audit_sink_profile_rejects_missing_sinks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.delenv("VINCTOR_AUDIT_ANCHOR", raising=False)
    monkeypatch.delenv("VINCTOR_AUDIT_EXPORT", raising=False)
    monkeypatch.setenv("VINCTOR_AUDIT_SINK_REQUIRED", "true")
    conn = connect_sqlite(":memory:")

    # When / Then
    try:
        with pytest.raises(ValueError, match="VINCTOR_AUDIT_SINK_REQUIRED"):
            SQLiteV1Service(conn)
    finally:
        conn.close()


def test_default_audit_sink_profile_is_null_and_silent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given / When
    sinks = audit_sinks_from_env({})

    # Then
    assert isinstance(sinks.anchor, NullAnchor)
    assert isinstance(sinks.export, NullExport)
    assert capsys.readouterr() == ("", "")


def test_required_audit_sink_profile_accepts_stdout_anchor() -> None:
    # Given / When
    sinks = audit_sinks_from_env(
        {
            "VINCTOR_AUDIT_SINK_REQUIRED": "true",
            "VINCTOR_AUDIT_ANCHOR": "stdout",
        }
    )

    # Then
    assert isinstance(sinks.anchor, StdoutAnchor)
    assert isinstance(sinks.export, NullExport)


def test_required_audit_sink_profile_accepts_stdout_export() -> None:
    # Given / When
    sinks = audit_sinks_from_env(
        {
            "VINCTOR_AUDIT_SINK_REQUIRED": "true",
            "VINCTOR_AUDIT_EXPORT": "stdout",
        }
    )

    # Then
    assert isinstance(sinks.anchor, NullAnchor)
    assert isinstance(sinks.export, StdoutExport)


def test_required_audit_sink_profile_accepts_otlp_export() -> None:
    # Given / When
    sinks = audit_sinks_from_env(
        {
            "VINCTOR_AUDIT_SINK_REQUIRED": "true",
            "VINCTOR_AUDIT_EXPORT": "otlp-http:http://collector:4318/v1/logs",
        }
    )

    # Then
    assert isinstance(sinks.export, OtlpHttpExport)
    sinks.export.close()
