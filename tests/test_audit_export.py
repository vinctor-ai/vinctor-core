import json
import sqlite3
import threading
from datetime import UTC, datetime

from vinctor_core.models import AuditEvent
from vinctor_service.audit_export import (
    ExportingAuditWriter,
    FileExport,
    NullExport,
    OtlpHttpExport,
    StdoutExport,
    audit_export_from_env,
)
from vinctor_service.sqlite import SQLiteAuditWriter, SQLiteV1Service

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)


def _event(event_id: str = "evt_1") -> AuditEvent:
    return AuditEvent(
        event_id=event_id, event_type="action_permitted", decision="permit",
        reason="ok", workspace_id="ws_main", agent_id="agent_a", grant_id="grnt_1",
        grant_ref="grt_1", action="read", resource="repo/x",
        scope_attempted="read:repo/x", scope_matched="read:repo/*",
        boundary_id="bnd_1", runtime="claude-code", boundary_type="pretooluse",
        created_at=NOW,
    )


def test_null_export_is_noop() -> None:
    NullExport().emit(_event())  # does not raise


def test_stdout_export_writes_one_json_line_per_event(capsys) -> None:
    ev = _event()
    StdoutExport().emit(ev)
    assert capsys.readouterr().out == json.dumps(ev.to_dict(), sort_keys=True) + "\n"


def test_file_export_appends_one_json_line_per_event(tmp_path) -> None:
    path = tmp_path / "export.log"
    export = FileExport(str(path))
    ev1, ev2 = _event("evt_1"), _event("evt_2")
    export.emit(ev1)
    export.emit(ev2)
    assert path.read_text().splitlines() == [
        json.dumps(ev1.to_dict(), sort_keys=True),
        json.dumps(ev2.to_dict(), sort_keys=True),
    ]


def test_file_export_is_fail_open_on_write_error(tmp_path, capsys) -> None:
    # A directory path can't be opened as a file for appending → emit must NOT raise.
    export = FileExport(str(tmp_path))  # tmp_path is a directory
    export.emit(_event())  # swallowed, no exception
    assert "audit export emit failed" in capsys.readouterr().err


def test_export_from_env_selects_sink() -> None:
    assert isinstance(audit_export_from_env({}), NullExport)
    assert isinstance(audit_export_from_env({"VINCTOR_AUDIT_EXPORT": ""}), NullExport)
    assert isinstance(
        audit_export_from_env({"VINCTOR_AUDIT_EXPORT": "stdout"}), StdoutExport
    )
    assert isinstance(
        audit_export_from_env({"VINCTOR_AUDIT_EXPORT": "file:/tmp/x.log"}), FileExport
    )
    otlp = audit_export_from_env(
        {"VINCTOR_AUDIT_EXPORT": "otlp-http:http://collector:4318/v1/logs"}
    )
    assert isinstance(otlp, OtlpHttpExport)
    otlp.close()


def test_otlp_http_export_emits_otlp_json_off_the_caller_thread() -> None:
    sent: list[tuple[str, bytes, float]] = []
    called = threading.Event()

    def sender(endpoint: str, data: bytes, timeout: float) -> None:
        sent.append((endpoint, data, timeout))
        called.set()

    export = OtlpHttpExport(
        "http://collector:4318/v1/logs",
        sender=sender,
    )
    export.emit(_event())
    assert called.wait(1)
    export.close()

    endpoint, data, timeout = sent[0]
    assert endpoint == "http://collector:4318/v1/logs"
    assert timeout == 1.0
    payload = json.loads(data)
    record = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    assert record["timeUnixNano"] == str(
        int(NOW.timestamp()) * 1_000_000_000 + NOW.microsecond * 1_000
    )
    assert json.loads(record["body"]["stringValue"])["event_id"] == "evt_1"
    assert {
        attribute["key"]: attribute["value"]["stringValue"]
        for attribute in record["attributes"]
    } == {
        "vinctor.event_id": "evt_1",
        "vinctor.event_type": "action_permitted",
        "vinctor.decision": "permit",
        "vinctor.workspace_id": "ws_main",
        "vinctor.agent_id": "agent_a",
        "vinctor.runtime": "claude-code",
    }
    resource_attributes = payload["resourceLogs"][0]["resource"]["attributes"]
    assert resource_attributes == [
        {"key": "service.name", "value": {"stringValue": "vinctor"}}
    ]


def test_otlp_http_export_is_fail_open_when_sender_fails(capsys) -> None:
    called = threading.Event()

    def sender(endpoint: str, data: bytes, timeout: float) -> None:
        called.set()
        raise OSError("collector down")

    export = OtlpHttpExport("http://collector:4318/v1/logs", sender=sender)
    export.emit(_event())
    assert called.wait(1)
    export.close()
    assert "audit export emit failed (otlp-http)" in capsys.readouterr().err


def test_otlp_http_export_drops_when_bounded_queue_is_full(capsys) -> None:
    entered = threading.Event()
    release = threading.Event()

    def sender(endpoint: str, data: bytes, timeout: float) -> None:
        entered.set()
        assert release.wait(1)

    export = OtlpHttpExport(
        "http://collector:4318/v1/logs",
        queue_size=1,
        sender=sender,
    )
    export.emit(_event("evt_1"))
    assert entered.wait(1)
    export.emit(_event("evt_2"))
    export.emit(_event("evt_3"))
    assert "queue full (otlp-http)" in capsys.readouterr().err
    release.set()
    export.close()


def test_export_from_env_rejects_invalid_otlp_http_endpoint(capsys) -> None:
    export = audit_export_from_env(
        {"VINCTOR_AUDIT_EXPORT": "otlp-http:collector:4318/v1/logs"}
    )
    assert isinstance(export, NullExport)
    assert "invalid VINCTOR_AUDIT_EXPORT" in capsys.readouterr().err


def test_export_from_env_unknown_spec_is_off_with_warning(capsys) -> None:
    export = audit_export_from_env({"VINCTOR_AUDIT_EXPORT": "otlp:collector:4317"})
    assert isinstance(export, NullExport)
    assert "unknown VINCTOR_AUDIT_EXPORT" in capsys.readouterr().err


class _SpyWriter:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


class _RaisingExport:
    def emit(self, event: AuditEvent) -> None:
        raise RuntimeError("sink down")


def test_exporting_writer_persists_first_then_emits() -> None:
    calls: list[tuple[str, AuditEvent]] = []

    class _Writer:
        def write(self, event: AuditEvent) -> None:
            calls.append(("write", event))

    class _Export:
        def emit(self, event: AuditEvent) -> None:
            calls.append(("emit", event))

    ev = _event()
    ExportingAuditWriter(_Writer(), _Export()).write(ev)
    assert calls == [("write", ev), ("emit", ev)]


def test_exporting_writer_is_fail_open_when_export_raises(capsys) -> None:
    wrapped = _SpyWriter()
    writer = ExportingAuditWriter(wrapped, _RaisingExport())
    writer.write(_event())  # must NOT raise
    # The durable path completed despite the broken sink.
    assert [e.event_id for e in wrapped.events] == ["evt_1"]
    assert "audit export emit failed" in capsys.readouterr().err


def test_sqlite_service_writer_is_unwrapped_when_env_unset(monkeypatch) -> None:
    monkeypatch.delenv("VINCTOR_AUDIT_EXPORT", raising=False)
    service = SQLiteV1Service(sqlite3.connect(":memory:"))
    assert type(service.audit_writer) is SQLiteAuditWriter


def test_sqlite_service_writer_exports_when_env_set(tmp_path, monkeypatch) -> None:
    path = tmp_path / "export.log"
    monkeypatch.setenv("VINCTOR_AUDIT_EXPORT", f"file:{path}")
    service = SQLiteV1Service(sqlite3.connect(":memory:"))
    assert isinstance(service.audit_writer, ExportingAuditWriter)

    ev = _event()
    service.audit_writer.write(ev)
    # Durable path unchanged: the event is persisted and readable via the
    # service's audit read paths (which go through the same writer object).
    assert [e.event_id for e in service.audit_events] == [ev.event_id]
    # ... and ALSO streamed to the export sink as one JSON line.
    assert json.loads(path.read_text().splitlines()[0]) == ev.to_dict()
