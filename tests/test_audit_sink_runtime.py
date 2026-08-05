from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vinctor_core.models import AuditEvent, Grant
from vinctor_service.audit_export import ExportingAuditWriter
from vinctor_service.models import GrantRequestCreateRequest, V1EnforceRequest
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 7, 19, 4, 0, tzinfo=UTC)


class _RaisingExport:
    def emit(self, event: AuditEvent) -> None:
        raise RuntimeError("sink down")


def _service_with_raising_export(
    monkeypatch: pytest.MonkeyPatch,
) -> SQLiteV1Service:
    monkeypatch.delenv("VINCTOR_AUDIT_ANCHOR", raising=False)
    monkeypatch.delenv("VINCTOR_AUDIT_SINK_REQUIRED", raising=False)
    monkeypatch.setenv("VINCTOR_AUDIT_EXPORT", "stdout")
    service = SQLiteV1Service(connect_sqlite(":memory:"))
    assert isinstance(service.audit_writer, ExportingAuditWriter)
    service.audit_writer._export = _RaisingExport()
    service.agent_enforcement_settings_repository.set_require_boundary(
        workspace_id="ws_main",
        agent_id="agent_release",
        require_boundary=False,
        now=NOW,
    )
    return service


def _grant() -> Grant:
    return Grant(
        grant_id="grnt_main",
        grant_ref="grt_main",
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


def _enforce_request() -> V1EnforceRequest:
    return V1EnforceRequest(
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        action="write",
        resource="repo/feature/readme",
    )


def _grant_request() -> GrantRequestCreateRequest:
    return GrantRequestCreateRequest(
        workspace_id="ws_main",
        requester_agent_id="agent_release",
        requested_scopes=("write:repo/feature/*",),
        requested_ttl_seconds=3600,
        reason="prepare release",
        request_id="grq_main",
    )


def test_sqlite_runtime_raising_export_does_not_block_decision_or_chain(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given
    service = _service_with_raising_export(monkeypatch)
    service.insert_grant(_grant())

    # When
    try:
        response = service.enforce(_enforce_request(), now=NOW)
        chain_ok = service.audit_writer.verify_chain().ok
    finally:
        service.conn.close()

    # Then
    assert response.status_code == 200
    assert response.decision == "permit"
    assert "sink down" not in repr(response)
    assert chain_ok is True
    assert "audit export emit failed" in capsys.readouterr().err


def test_sqlite_runtime_raising_export_does_not_roll_back_state(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given
    service = _service_with_raising_export(monkeypatch)

    # When
    try:
        created = service.create_grant_request(_grant_request(), now=NOW)
        persisted = service.lookup_grant_request(
            request_id="grq_main",
            workspace_id="ws_main",
        )
        chain_ok = service.audit_writer.verify_chain().ok
    finally:
        service.conn.close()

    # Then
    assert created.status == "created"
    assert persisted == created.request
    assert chain_ok is True
    assert "audit export emit failed" in capsys.readouterr().err


def test_sqlite_chain_verifies_after_sink_misconfiguration_is_corrected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.delenv("VINCTOR_AUDIT_ANCHOR", raising=False)
    monkeypatch.delenv("VINCTOR_AUDIT_SINK_REQUIRED", raising=False)
    monkeypatch.setenv("VINCTOR_AUDIT_EXPORT", "unknown:sink")
    rejected_conn = connect_sqlite(":memory:")
    try:
        with pytest.raises(ValueError, match="VINCTOR_AUDIT_EXPORT"):
            SQLiteV1Service(rejected_conn)
    finally:
        rejected_conn.close()
    destination = tmp_path / "audit.jsonl"
    monkeypatch.setenv("VINCTOR_AUDIT_EXPORT", f"file:{destination}")
    service = SQLiteV1Service(connect_sqlite(":memory:"))

    # When
    try:
        created = service.create_grant_request(_grant_request(), now=NOW)
        chain_ok = service.audit_writer.verify_chain().ok
    finally:
        service.conn.close()

    # Then
    assert created.status == "created"
    assert chain_ok is True
    assert destination.read_text(encoding="utf-8").count("\n") == 1
