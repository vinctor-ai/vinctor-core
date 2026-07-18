from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from vinctor_mcp_server.tools import (
    VinctorReadOnlyTools,
    VinctorWriteTools,
    register_read_only_tools,
    register_write_tools,
)


class FakeClient:
    def status(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "vinctor-service",
            "mode": "local",
            "db_path": "/private/vinctor.sqlite",
            "key_hash": "secret",
        }

    def list_boundaries(self) -> dict[str, Any]:
        return {
            "boundaries": [
                {
                    "boundary_id": "bnd_main",
                    "name": "codex-local",
                    "runtime": "codex",
                    "boundary_type": "pretooluse",
                    "mode": "fail_closed",
                    "status": "active",
                    "key_hash": "secret",
                }
            ]
        }

    def get_boundary(self, boundary_id: str) -> dict[str, Any]:
        return {
            "boundary_id": boundary_id,
            "name": "codex-local",
            "runtime": "codex",
            "boundary_type": "pretooluse",
            "mode": "fail_closed",
            "status": "active",
            "raw_prompt": "hidden",
        }

    def get_grant(self, grant_ref: str) -> dict[str, Any]:
        return {
            "grant_id": "grnt_main",
            "grant_ref": grant_ref,
            "workspace_id": "ws_main",
            "agent_id": "agent_release",
            "scopes": ["write:repo/feature/*"],
            "status": "active",
            "expires_at": "2026-06-11T12:00:00+00:00",
            "raw_key": "wsk_secret",
            "key_hash": "hash_secret",
        }

    def list_grants(
        self,
        *,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        return {
            "grants": [
                {
                    "grant_id": "grnt_email",
                    "grant_ref": "grt_email",
                    "workspace_id": "ws_main",
                    "agent_id": agent_id or "agent_release",
                    "scopes": ["send:email/*"],
                    "status": status or "active",
                    "expires_at": "2999-06-11T12:00:00+00:00",
                    "raw_key": "wsk_secret",
                    "key_hash": "hash_secret",
                },
                {
                    "grant_id": "grnt_repo",
                    "grant_ref": "grt_repo",
                    "workspace_id": "ws_main",
                    "agent_id": agent_id or "agent_release",
                    "scopes": ["write:repo/feature/*"],
                    "status": status or "active",
                    "expires_at": "2999-06-11T12:00:00+00:00",
                },
                {
                    "grant_id": "grnt_revoked",
                    "grant_ref": "grt_revoked",
                    "workspace_id": "ws_main",
                    "agent_id": agent_id or "agent_release",
                    "scopes": ["send:email/*"],
                    "status": "revoked",
                    "expires_at": "2999-06-11T12:00:00+00:00",
                },
                {
                    "grant_id": "grnt_expired",
                    "grant_ref": "grt_expired",
                    "workspace_id": "ws_main",
                    "agent_id": agent_id or "agent_release",
                    "scopes": ["send:email/*"],
                    "status": status or "active",
                    "expires_at": "2000-06-11T12:00:00+00:00",
                },
            ]
        }

    def list_audit_events(
        self,
        *,
        limit: int = 20,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        request_id: str | None = None,
        agent_id: str | None = None,
        reason_code: str | None = None,
        enforcing_principal: str | None = None,
        subject_token_verified: bool | None = None,
    ) -> dict[str, Any]:
        return {
            "audit_events": [
                {
                    "event_id": "evt_deny",
                    "event_type": event_type or "action_denied",
                    "decision": "deny",
                    "reason": "action_denied",
                    "workspace_id": "ws_main",
                    "agent_id": "agent_release",
                    "grant_id": "grnt_main",
                    "grant_ref": grant_ref or "grt_main",
                    "action": "send",
                    "resource": "email/external",
                    "scope_attempted": "send:email/external",
                    "scope_matched": None,
                    "boundary_id": boundary_id,
                    "runtime": None,
                    "boundary_type": None,
                    "created_at": "2026-06-11T12:00:00+00:00",
                    "enforcing_principal": enforcing_principal or "pep_git_host",
                    "reason_code": reason_code or "agent_grant_mismatch",
                    "occurrence_count": 3,
                    "first_seen_at": "2026-06-11T11:58:00+00:00",
                    "last_seen_at": "2026-06-11T12:00:00+00:00",
                    "subject_token_verified": (
                        subject_token_verified
                        if subject_token_verified is not None
                        else True
                    ),
                    "token_id": "vtk_secret_detail",
                    "event_json": {"raw": "hidden"},
                    "raw_command": "send-secret",
                    "key_hash": "hash_secret",
                    "limit_seen": limit,
                    "request_seen": request_id,
                    "agent_seen": agent_id,
                }
            ]
        }

    def get_audit_event(self, event_id: str) -> dict[str, Any]:
        return {
            "event_id": event_id,
            "event_type": "action_denied",
            "decision": "deny",
            "reason": "action_denied",
            "workspace_id": "ws_main",
            "agent_id": "agent_release",
            "grant_id": "grnt_main",
            "grant_ref": "grt_main",
            "action": "send",
            "resource": "email/external",
            "scope_attempted": "send:email/external",
            "scope_matched": None,
            "boundary_id": "bnd_main",
            "runtime": "codex",
            "boundary_type": "pretooluse",
            "created_at": "2026-06-11T12:00:00+00:00",
            "enforcing_principal": "pep_git_host",
            "reason_code": "agent_grant_mismatch",
            "occurrence_count": 3,
            "first_seen_at": "2026-06-11T11:58:00+00:00",
            "last_seen_at": "2026-06-11T12:00:00+00:00",
            "subject_token_verified": True,
            "token_id": "vtk_secret_detail",
            "raw_tool_input": {"secret": "hidden"},
        }

    def list_grant_requests(self) -> dict[str, Any]:
        return {
            "grant_requests": [
                {
                    "request_id": "grq_main",
                    "workspace_id": "ws_main",
                    "requester_agent_id": "agent_release",
                    "target_agent_id": "agent_release",
                    "requested_scopes": ["write:repo/feature/*"],
                    "requested_ttl_seconds": 300,
                    "reason": "operator-visible raw free text",
                    "status": "pending",
                    "created_at": "2026-06-11T12:00:00+00:00",
                    "decided_at": None,
                    "decided_by": "workspace:ws_main",
                    "decision_reason": None,
                    "issued_grant_ref": None,
                    "task_id": "task-secret",
                    "session_id": "session-secret",
                    "boundary_id": "bnd_main",
                    "requester_runtime": "codex",
                    "repo": "private/repo",
                    "worktree": "/private/tmp/worktree",
                    "routing_hint": "manual_review_required",
                    "routing_reason": "no_matching_auto_approval_rule",
                    "queue_reason": "no_matching_auto_approval_rule",
                    "raw_tool_input": {"secret": "hidden"},
                }
            ]
        }

    def get_grant_request(self, request_id: str) -> dict[str, Any]:
        request = self.list_grant_requests()["grant_requests"][0]
        request["request_id"] = request_id
        return request

    def list_auto_approval_rules(self) -> dict[str, Any]:
        return {
            "auto_approval_rules": [
                {
                    "rule_id": "aar_main",
                    "workspace_id": "ws_main",
                    "name": "CI auto approval",
                    "target_agent_id": "agent_release",
                    "allowed_scopes": ["write:repo/feature/*"],
                    "max_ttl_seconds": 3600,
                    "status": "active",
                    "created_by": "workspace:ws_main",
                    "created_at": "2026-06-11T12:00:00+00:00",
                    "updated_by": "workspace:ws_main",
                    "updated_at": None,
                    "raw_command": "hidden",
                    "key_hash": "hidden",
                }
            ]
        }

    def list_service_auth_failures(self, *, limit: int = 20) -> dict[str, Any]:
        return {
            "auth_failures": [
                {
                    "event_id": "evt_auth",
                    "event_type": "auth_failed",
                    "event_class": "security",
                    "reason_code": "auth_failed",
                    "occurrence_count": 4,
                    "first_seen_at": "2026-06-11T11:55:00+00:00",
                    "last_seen_at": "2026-06-11T12:00:00+00:00",
                    "subject_token_verified": False,
                    "token_id": "vtk_hidden",
                    "created_at": "2026-06-11T12:00:00+00:00",
                    "raw_key": "sok_secret",
                    "limit_seen": limit,
                }
            ]
        }


class FakeMcp:
    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., object]] = {}
        self.descriptions: dict[str, str] = {}

    def tool(self, *, name: str, description: str) -> Callable[[Callable[..., object]], object]:
        def register(fn: Callable[..., object]) -> object:
            self.tools[name] = fn
            self.descriptions[name] = description
            return fn

        return register


class RecordingAuditClient(FakeClient):
    def __init__(self) -> None:
        self.seen_limits: list[int] = []

    def list_audit_events(
        self,
        *,
        limit: int = 20,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        request_id: str | None = None,
        agent_id: str | None = None,
        reason_code: str | None = None,
        enforcing_principal: str | None = None,
        subject_token_verified: bool | None = None,
    ) -> dict[str, Any]:
        self.seen_limits.append(limit)
        return super().list_audit_events(
            limit=limit,
            event_type=event_type,
            grant_ref=grant_ref,
            boundary_id=boundary_id,
            request_id=request_id,
            agent_id=agent_id,
            reason_code=reason_code,
            enforcing_principal=enforcing_principal,
            subject_token_verified=subject_token_verified,
        )


def test_status_tool_redacts_service_internals() -> None:
    tools = VinctorReadOnlyTools(FakeClient())

    assert tools.status() == {
        "status": "ok",
        "service": "vinctor-service",
        "mode": "local",
    }


def test_boundary_tools_return_allowlisted_fields() -> None:
    tools = VinctorReadOnlyTools(FakeClient())

    assert tools.list_boundaries() == {
        "boundaries": [
            {
                "boundary_id": "bnd_main",
                "name": "codex-local",
                "runtime": "codex",
                "boundary_type": "pretooluse",
                "mode": "fail_closed",
                "status": "active",
            }
        ]
    }
    assert tools.get_boundary("bnd_main") == {
        "boundary_id": "bnd_main",
        "name": "codex-local",
        "runtime": "codex",
        "boundary_type": "pretooluse",
        "mode": "fail_closed",
        "status": "active",
    }


def test_get_grant_tool_returns_allowlisted_fields() -> None:
    tools = VinctorReadOnlyTools(FakeClient())

    assert tools.get_grant("grt_main") == {
        "grant_id": "grnt_main",
        "grant_ref": "grt_main",
        "workspace_id": "ws_main",
        "agent_id": "agent_release",
        "status": "active",
        "expires_at": "2026-06-11T12:00:00+00:00",
    }


def test_list_grants_tool_uses_safe_fields_by_default() -> None:
    tools = VinctorReadOnlyTools(FakeClient())

    listed = tools.list_grants(agent_id="agent_release", status="active")
    grant = listed["grants"][0]

    assert grant == {
        "grant_id": "grnt_email",
        "grant_ref": "grt_email",
        "workspace_id": "ws_main",
        "agent_id": "agent_release",
        "status": "active",
        "expires_at": "2999-06-11T12:00:00+00:00",
    }
    assert "scopes" not in grant
    assert "raw_key" not in grant
    assert "key_hash" not in grant


def test_diagnostic_mode_returns_scope_fields() -> None:
    tools = VinctorReadOnlyTools(FakeClient(), output_mode="diagnostic")

    grant = tools.get_grant("grt_main")
    listed_grant = tools.list_grants(agent_id="agent_release", status="active")["grants"][0]
    event = tools.list_audit_events(limit=5, event_type="action_denied")["audit_events"][0]
    request = tools.list_grant_requests()["grant_requests"][0]
    rule = tools.list_auto_approval_rules()["auto_approval_rules"][0]

    assert grant["scopes"] == ["write:repo/feature/*"]
    assert listed_grant["scopes"] == ["send:email/*"]
    assert event["scope_attempted"] == "send:email/external"
    assert event["scope_matched"] is None
    assert event["token_id"] == "vtk_secret_detail"
    assert request["requested_scopes"] == ["write:repo/feature/*"]
    assert rule["allowed_scopes"] == ["write:repo/feature/*"]


def test_audit_tools_use_safe_fields_by_default() -> None:
    tools = VinctorReadOnlyTools(FakeClient())

    listed = tools.list_audit_events(limit=5, event_type="action_denied")
    event = listed["audit_events"][0]
    assert event == {
        "event_id": "evt_deny",
        "event_type": "action_denied",
        "decision": "deny",
        "reason": "action_denied",
        "workspace_id": "ws_main",
        "agent_id": "agent_release",
        "grant_id": "grnt_main",
        "grant_ref": "grt_main",
        "action": "send",
        "resource": "email/external",
        "boundary_id": None,
        "runtime": None,
        "boundary_type": None,
        "created_at": "2026-06-11T12:00:00+00:00",
        "enforcing_principal": "pep_git_host",
        "reason_code": "agent_grant_mismatch",
        "occurrence_count": 3,
        "first_seen_at": "2026-06-11T11:58:00+00:00",
        "last_seen_at": "2026-06-11T12:00:00+00:00",
        "subject_token_verified": True,
    }
    assert "scope_attempted" not in event
    assert "scope_matched" not in event
    assert "token_id" not in event
    assert "event_json" not in event
    assert "raw_command" not in event
    assert "key_hash" not in event

    fetched = tools.get_audit_event("evt_deny")
    assert fetched["event_id"] == "evt_deny"
    assert "raw_tool_input" not in fetched


def test_list_audit_events_clamps_limit_before_calling_service() -> None:
    client = RecordingAuditClient()
    tools = VinctorReadOnlyTools(client)

    tools.list_audit_events(limit=500)
    tools.list_audit_events(limit=0)

    assert client.seen_limits == [100, 1]


def test_list_audit_events_passes_agent_id_filter() -> None:
    class RecordingClient(FakeClient):
        def __init__(self) -> None:
            self.seen_agent_id: str | None = None

        def list_audit_events(
            self,
            *,
            limit: int = 20,
            event_type: str | None = None,
            grant_ref: str | None = None,
            boundary_id: str | None = None,
            request_id: str | None = None,
            agent_id: str | None = None,
            reason_code: str | None = None,
            enforcing_principal: str | None = None,
            subject_token_verified: bool | None = None,
        ) -> dict[str, Any]:
            self.seen_agent_id = agent_id
            return super().list_audit_events(
                limit=limit,
                event_type=event_type,
                grant_ref=grant_ref,
                boundary_id=boundary_id,
                request_id=request_id,
                agent_id=agent_id,
                reason_code=reason_code,
                enforcing_principal=enforcing_principal,
                subject_token_verified=subject_token_verified,
            )

    client = RecordingClient()
    tools = VinctorReadOnlyTools(client)

    tools.list_audit_events(agent_id="agent_release")

    assert client.seen_agent_id == "agent_release"


def test_list_audit_events_passes_security_filters() -> None:
    class RecordingClient(FakeClient):
        def __init__(self) -> None:
            self.seen: tuple[str | None, str | None, bool | None] | None = None

        def list_audit_events(
            self,
            *,
            limit: int = 20,
            event_type: str | None = None,
            grant_ref: str | None = None,
            boundary_id: str | None = None,
            request_id: str | None = None,
            agent_id: str | None = None,
            reason_code: str | None = None,
            enforcing_principal: str | None = None,
            subject_token_verified: bool | None = None,
        ) -> dict[str, Any]:
            self.seen = (reason_code, enforcing_principal, subject_token_verified)
            return super().list_audit_events(
                limit=limit,
                event_type=event_type,
                grant_ref=grant_ref,
                boundary_id=boundary_id,
                request_id=request_id,
                agent_id=agent_id,
                reason_code=reason_code,
                enforcing_principal=enforcing_principal,
                subject_token_verified=subject_token_verified,
            )

    client = RecordingClient()

    VinctorReadOnlyTools(client).list_audit_events(
        reason_code="agent_key_invalid",
        enforcing_principal="pep_git_host",
        subject_token_verified=False,
    )

    assert client.seen == ("agent_key_invalid", "pep_git_host", False)


def test_explain_denial_uses_safe_fields_by_default() -> None:
    tools = VinctorReadOnlyTools(FakeClient())

    explanation = tools.explain_denial(event_id="evt_deny")

    assert explanation == {
        "event_id": "evt_deny",
        "decision": "deny",
        "reason": "action_denied",
        "action": "send",
        "resource": "email/external",
        "boundary_id": "bnd_main",
        "grant_ref": "grt_main",
        "explanation": (
            "Vinctor denied the request because the issued grant did not permit "
            "the requested action/resource."
        ),
    }
    assert "scope_attempted" not in explanation
    assert "scope_matched" not in explanation
    assert "missing_scope" not in explanation
    assert "would_be_allowed_by" not in explanation
    assert "raw_tool_input" not in explanation


def test_explain_denial_diagnostic_mode_includes_authorization_hints() -> None:
    tools = VinctorReadOnlyTools(FakeClient(), output_mode="diagnostic")

    explanation = tools.explain_denial(event_id="evt_deny")

    assert explanation["scope_attempted"] == "send:email/external"
    assert explanation["scope_matched"] is None
    assert explanation["missing_scope"] == "send:email/external"
    assert explanation["would_be_allowed_by"] == ["grt_email"]


def test_explain_denial_keeps_missing_scope_empty_for_non_denial() -> None:
    class PermitClient(FakeClient):
        def get_audit_event(self, event_id: str) -> dict[str, Any]:
            event = super().get_audit_event(event_id)
            event["decision"] = "permit"
            event["scope_matched"] = "send:email/external"
            return event

    tools = VinctorReadOnlyTools(PermitClient())

    explanation = tools.explain_denial(event_id="evt_permit")

    assert explanation["decision"] == "permit"
    assert "missing_scope" not in explanation
    assert "would_be_allowed_by" not in explanation
    assert explanation["explanation"] == "This audit event is not a denial."


class ReportClient(FakeClient):
    """A client whose audit feed mixes grant lifecycle events with enforcement
    usage events (permit + deny), and smuggles leak bait into the grant,
    boundary, and every audit event, to pin the report compose + leak discipline."""

    def __init__(self) -> None:
        self.get_grant_calls: list[str] = []
        self.get_boundary_calls: list[str] = []
        self.audit_calls: list[dict[str, Any]] = []

    def get_grant(self, grant_ref: str) -> dict[str, Any]:
        self.get_grant_calls.append(grant_ref)
        return super().get_grant(grant_ref)

    def get_boundary(self, boundary_id: str) -> dict[str, Any]:
        self.get_boundary_calls.append(boundary_id)
        return super().get_boundary(boundary_id)

    def list_audit_events(
        self,
        *,
        limit: int = 20,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        request_id: str | None = None,
        agent_id: str | None = None,
        reason_code: str | None = None,
        enforcing_principal: str | None = None,
        subject_token_verified: bool | None = None,
    ) -> dict[str, Any]:
        self.audit_calls.append(
            {
                "limit": limit,
                "event_type": event_type,
                "grant_ref": grant_ref,
                "boundary_id": boundary_id,
                "request_id": request_id,
                "agent_id": agent_id,
                "reason_code": reason_code,
                "enforcing_principal": enforcing_principal,
                "subject_token_verified": subject_token_verified,
            }
        )

        def event(
            event_id: str,
            etype: str,
            decision: str | None,
        ) -> dict[str, Any]:
            return {
                "event_id": event_id,
                "event_type": etype,
                "decision": decision,
                "reason": etype,
                "workspace_id": "ws_main",
                "agent_id": "agent_release",
                "grant_id": "grnt_main",
                "grant_ref": grant_ref or "grt_main",
                "action": "send",
                "resource": "email/external",
                "scope_attempted": "send:email/external",
                "scope_matched": None,
                "boundary_id": boundary_id,
                "runtime": None,
                "boundary_type": None,
                "created_at": "2026-06-11T12:00:00+00:00",
                "event_json": {"raw": "hidden"},
                "raw_command": "send-secret",
                "raw_key": "wsk_secret",
                "key_hash": "hash_secret",
                "raw_tool_input": {"secret": "hidden"},
            }

        return {
            "audit_events": [
                event("evt_issued", "grant_issued", None),
                event("evt_permit", "action_permitted", "permit"),
                event("evt_deny", "action_denied", "deny"),
                event("evt_reject", "access_rejected", "deny"),
                event("evt_revoked", "grant_revoked", None),
            ]
        }


def test_grant_report_partitions_lifecycle_and_usage() -> None:
    client = ReportClient()
    tools = VinctorReadOnlyTools(client)

    report = tools.grant_report("grt_x")

    assert report["grant"] == {
        "grant_id": "grnt_main",
        "grant_ref": "grt_x",
        "workspace_id": "ws_main",
        "agent_id": "agent_release",
        "status": "active",
        "expires_at": "2026-06-11T12:00:00+00:00",
    }
    assert [e["event_id"] for e in report["lifecycle"]] == ["evt_issued", "evt_revoked"]
    assert [e["event_id"] for e in report["usage"]] == [
        "evt_permit",
        "evt_deny",
        "evt_reject",
    ]
    assert client.get_grant_calls == ["grt_x"]
    assert len(client.audit_calls) == 1
    assert client.audit_calls[0]["grant_ref"] == "grt_x"
    assert client.audit_calls[0]["boundary_id"] is None


def test_grant_report_never_leaks_raw_keys_hashes_or_internals() -> None:
    for mode in ("safe", "diagnostic"):
        tools = VinctorReadOnlyTools(ReportClient(), output_mode=mode)

        blob = json.dumps(tools.grant_report("grt_x"))

        for forbidden in (
            "wsk_",
            "hash_secret",
            "raw_tool_input",
            "raw_key",
            "key_hash",
            "event_json",
            "raw_command",
        ):
            assert forbidden not in blob


def test_boundary_report_summarizes_permit_deny_activity() -> None:
    client = ReportClient()
    tools = VinctorReadOnlyTools(client)

    report = tools.boundary_report("bnd_x")

    assert report["boundary"] == {
        "boundary_id": "bnd_x",
        "name": "codex-local",
        "runtime": "codex",
        "boundary_type": "pretooluse",
        "mode": "fail_closed",
        "status": "active",
    }
    assert report["activity"] == {"permit": 1, "deny": 2}
    assert [e["event_id"] for e in report["recent"]] == [
        "evt_issued",
        "evt_permit",
        "evt_deny",
        "evt_reject",
        "evt_revoked",
    ]
    assert client.get_boundary_calls == ["bnd_x"]
    assert len(client.audit_calls) == 1
    assert client.audit_calls[0]["boundary_id"] == "bnd_x"
    assert client.audit_calls[0]["grant_ref"] is None


def test_boundary_report_never_leaks_raw_keys_hashes_or_internals() -> None:
    for mode in ("safe", "diagnostic"):
        tools = VinctorReadOnlyTools(ReportClient(), output_mode=mode)

        blob = json.dumps(tools.boundary_report("bnd_x"))

        for forbidden in (
            "wsk_",
            "hash_secret",
            "raw_tool_input",
            "raw_key",
            "key_hash",
            "event_json",
            "raw_command",
            "raw_prompt",
        ):
            assert forbidden not in blob


def test_report_tools_registered_as_read_tools_when_write_disabled() -> None:
    mcp = FakeMcp()

    register_read_only_tools(mcp, FakeClient())

    assert "vinctor_grant_report" in mcp.tools
    assert "vinctor_boundary_report" in mcp.tools
    assert "vinctor_grant_request_report" in mcp.tools


def test_grant_request_tools_return_allowlisted_fields() -> None:
    tools = VinctorReadOnlyTools(FakeClient())

    listed = tools.list_grant_requests()
    request = listed["grant_requests"][0]

    assert request == {
        "request_id": "grq_main",
        "workspace_id": "ws_main",
        "requester_agent_id": "agent_release",
        "target_agent_id": "agent_release",
        "requested_ttl_seconds": 300,
        "reason": "operator-visible raw free text",
        "status": "pending",
        "created_at": "2026-06-11T12:00:00+00:00",
        "decided_at": None,
        "decision_reason": None,
        "issued_grant_ref": None,
        "boundary_id": "bnd_main",
        "requester_runtime": "codex",
        "routing_hint": "manual_review_required",
        "routing_reason": "no_matching_auto_approval_rule",
        "queue_reason": "no_matching_auto_approval_rule",
    }
    assert tools.get_grant_request("grq_other")["request_id"] == "grq_other"
    assert "requested_scopes" not in request
    assert "task_id" not in request
    assert "session_id" not in request
    assert "repo" not in request
    assert "worktree" not in request
    assert "decided_by" not in request
    assert "raw_tool_input" not in request


def test_list_grant_requests_filters_status_locally() -> None:
    class MixedStatusClient(FakeClient):
        def list_grant_requests(self) -> dict[str, Any]:
            pending = super().list_grant_requests()["grant_requests"][0]
            return {
                "grant_requests": [
                    pending,
                    {**pending, "request_id": "grq_approved", "status": "approved"},
                ]
            }

    listed = VinctorReadOnlyTools(MixedStatusClient()).list_grant_requests(
        status="approved"
    )

    assert [request["request_id"] for request in listed["grant_requests"]] == [
        "grq_approved"
    ]


def test_grant_request_report_correlates_request_and_issued_grant_audit() -> None:
    class GrantRequestReportClient(ReportClient):
        def get_grant_request(self, request_id: str) -> dict[str, Any]:
            request = super().get_grant_request(request_id)
            request["issued_grant_ref"] = "grt_issued"
            return request

    client = GrantRequestReportClient()

    report = VinctorReadOnlyTools(client).grant_request_report("grq_main")

    assert report["grant_request"]["request_id"] == "grq_main"
    assert report["grant"]["grant_ref"] == "grt_issued"
    assert [event["event_id"] for event in report["timeline"]] == [
        "evt_issued",
        "evt_permit",
        "evt_deny",
        "evt_reject",
        "evt_revoked",
    ]
    assert [call["request_id"] for call in client.audit_calls] == ["grq_main", None]
    assert [call["grant_ref"] for call in client.audit_calls] == [None, "grt_issued"]
    for forbidden in ("wsk_", "raw_tool_input", "key_hash", "event_json"):
        assert forbidden not in json.dumps(report)


def test_auto_approval_rule_tool_returns_allowlisted_fields() -> None:
    tools = VinctorReadOnlyTools(FakeClient())

    listed = tools.list_auto_approval_rules()
    rule = listed["auto_approval_rules"][0]

    assert rule == {
        "rule_id": "aar_main",
        "workspace_id": "ws_main",
        "name": "CI auto approval",
        "target_agent_id": "agent_release",
        "max_ttl_seconds": 3600,
        "status": "active",
        "created_by": "workspace:ws_main",
        "created_at": "2026-06-11T12:00:00+00:00",
        "updated_by": "workspace:ws_main",
        "updated_at": None,
    }
    assert "allowed_scopes" not in rule
    assert "raw_command" not in rule
    assert "key_hash" not in rule


def test_service_auth_failures_use_audit_allowlist_and_limit_cap() -> None:
    tools = VinctorReadOnlyTools(FakeClient())

    event = tools.list_service_auth_failures(limit=500)["auth_failures"][0]

    assert event == {
        "event_id": "evt_auth",
        "event_type": "auth_failed",
        "event_class": "security",
        "reason_code": "auth_failed",
        "occurrence_count": 4,
        "first_seen_at": "2026-06-11T11:55:00+00:00",
        "last_seen_at": "2026-06-11T12:00:00+00:00",
        "subject_token_verified": False,
        "created_at": "2026-06-11T12:00:00+00:00",
    }
    assert "token_id" not in event
    assert "raw_key" not in event


class NestedLeakClient(FakeClient):
    """A service whose responses smuggle secrets *inside* allowlisted container
    fields (mode/scopes/action). allowlist_object only filters the top level, so
    these nested values currently flow through. Documents finding H1."""

    def status(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "vinctor-service",
            "mode": {"agent_key": "aak_REAL_SECRET", "db_path": "/var/vinctor/secrets.db"},
        }

    def get_grant(self, grant_ref: str) -> dict[str, Any]:
        return {
            "grant_id": "grnt_main",
            "grant_ref": grant_ref,
            "workspace_id": "ws_main",
            "agent_id": "agent_release",
            "scopes": [{"scope": "write:repo/feature/*", "raw_key": "wsk_secret"}],
            "status": "active",
            "expires_at": "2026-06-11T12:00:00+00:00",
        }

    def get_audit_event(self, event_id: str) -> dict[str, Any]:
        return {
            "event_id": event_id,
            "event_type": "action_denied",
            "decision": "deny",
            "reason": "action_denied",
            "workspace_id": "ws_main",
            "agent_id": "agent_release",
            "grant_id": "grnt_main",
            "grant_ref": "grt_main",
            "action": {"verb": "send", "raw_tool_input": {"secret": "hidden"}},
            "resource": "email/external",
            "scope_attempted": "send:email/external",
            "scope_matched": None,
            "boundary_id": "bnd_main",
            "runtime": "codex",
            "boundary_type": "pretooluse",
            "created_at": "2026-06-11T12:00:00+00:00",
        }

    def list_grant_requests(self) -> dict[str, Any]:
        return {
            "grant_requests": [
                {
                    "request_id": "grq_main",
                    "requested_scopes": [{"scope": "write:repo/*", "raw_key": "wsk_secret"}],
                    "requested_ttl_seconds": {"raw_tool_input": "hidden"},
                    "status": "pending",
                }
            ]
        }

    def list_grants(
        self,
        *,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        return {
            "grants": [
                {
                    "grant_ref": "grt_secret",
                    "scopes": [{"scope": "send:email/*", "raw_key": "wsk_secret"}],
                    "status": status or "active",
                    "raw_tool_input": {"secret": "hidden"},
                }
            ]
        }

    def list_auto_approval_rules(self) -> dict[str, Any]:
        return {
            "auto_approval_rules": [
                {
                    "rule_id": "aar_main",
                    "allowed_scopes": [{"scope": "write:repo/*", "raw_key": "wsk_secret"}],
                    "max_ttl_seconds": {"db_path": "/private/vinctor.sqlite"},
                    "status": "active",
                }
            ]
        }


def test_allowlisting_strips_disallowed_fields_nested_in_containers() -> None:
    """Nested values inside allowlisted fields are type-checked before output."""
    tools = VinctorReadOnlyTools(NestedLeakClient())

    blob = json.dumps(
        [
            tools.status(),
            tools.get_grant("grt_main"),
            tools.get_audit_event("evt_deny"),
            tools.list_grants(),
            tools.explain_denial(event_id="evt_deny"),
            tools.list_grant_requests(),
            tools.list_auto_approval_rules(),
        ]
    )

    for forbidden in ("aak_", "wsk_", "db_path", "raw_tool_input", "raw_key"):
        assert forbidden not in blob


def test_registers_only_read_only_mvp_tools() -> None:
    mcp = FakeMcp()

    register_read_only_tools(mcp, FakeClient())

    assert sorted(mcp.tools) == [
        "vinctor_boundary_report",
        "vinctor_explain_denial",
        "vinctor_get_audit_event",
        "vinctor_get_boundary",
        "vinctor_get_grant",
        "vinctor_get_grant_request",
        "vinctor_grant_report",
        "vinctor_grant_request_report",
        "vinctor_list_audit_events",
        "vinctor_list_auto_approval_rules",
        "vinctor_list_boundaries",
        "vinctor_list_grant_requests",
        "vinctor_list_grants",
        "vinctor_list_service_auth_failures",
        "vinctor_status",
    ]
    assert not any("approve" in name for name in mcp.tools)
    assert not any("reject" in name for name in mcp.tools)
    assert not any("revoke" in name for name in mcp.tools)
    assert not any("issue" in name for name in mcp.tools)


def test_audit_list_tool_description_mentions_limit_cap() -> None:
    mcp = FakeMcp()

    register_read_only_tools(mcp, FakeClient())

    description = mcp.descriptions["vinctor_list_audit_events"]
    assert "1..100 cap" in description


class FakeDecisionClient(FakeClient):
    """A client whose approve/reject responses smuggle service internals
    (raw keys/hashes/internal fields) at the top level and inside the issued
    grant, to pin the write-tool leak discipline."""

    def __init__(self) -> None:
        self.approved: list[tuple[str, str | None]] = []
        self.auto_approved: list[str] = []
        self.rejected: list[tuple[str, str | None]] = []
        self.revoked: list[str] = []
        self.issued: list[tuple[str, list[str], int]] = []
        self.created_boundaries: list[tuple[str, str, str, str]] = []
        self.enabled_boundaries: list[str] = []
        self.disabled_boundaries: list[str] = []
        self.created_rules: list[tuple[str, str, list[str], int]] = []
        self.disabled_rules: list[str] = []

    def _decision_response(self, request_id: str, status: str) -> dict[str, Any]:
        return {
            "request_id": request_id,
            "workspace_id": "ws_main",
            "requester_agent_id": "agent_release",
            "target_agent_id": "agent_release",
            "requested_scopes": ["write:repo/feature/*"],
            "requested_ttl_seconds": 300,
            "status": status,
            "created_at": "2026-06-11T12:00:00+00:00",
            "decided_at": "2026-06-11T12:05:00+00:00",
            "decided_by": "workspace:ws_main",
            "decision_reason": "operator note",
            "issued_grant_ref": "grt_issued",
            "boundary_id": "bnd_main",
            "requester_runtime": "codex",
            "routing_hint": "manual_review_required",
            "routing_reason": "no_matching_auto_approval_rule",
            "queue_reason": "no_matching_auto_approval_rule",
            "audit_event_id": "evt_decision",
            "raw_tool_input": {"secret": "hidden"},
            "key_hash": "hash_secret",
            "grant": {
                "grant_id": "grnt_issued",
                "grant_ref": "grt_issued",
                "workspace_id": "ws_main",
                "agent_id": "agent_release",
                "scopes": ["write:repo/feature/*"],
                "status": "active",
                "expires_at": "2999-06-11T12:00:00+00:00",
                "raw_key": "wsk_secret",
                "key_hash": "hash_secret",
            },
        }

    def approve_grant_request(
        self,
        request_id: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        self.approved.append((request_id, reason))
        return self._decision_response(request_id, "approved")

    def reject_grant_request(
        self,
        request_id: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        self.rejected.append((request_id, reason))
        return self._decision_response(request_id, "rejected")

    def auto_approve_grant_request(self, request_id: str) -> dict[str, Any]:
        self.auto_approved.append(request_id)
        body = self._decision_response(request_id, "approved")
        body["auto_approval"] = {
            "decision": "approved",
            "reason": "matched",
            "rule_id": "apr_main",
            "raw_key": "wsk_hidden",
        }
        return body

    def revoke_grant(self, grant_ref: str) -> dict[str, Any]:
        self.revoked.append(grant_ref)
        return {
            "grant_id": "grnt_revoked",
            "grant_ref": grant_ref,
            "workspace_id": "ws_main",
            "agent_id": "agent_release",
            "scopes": ["write:repo/feature/*"],
            "status": "revoked",
            "expires_at": "2999-06-11T12:00:00+00:00",
            "audit_event_id": "evt_revoke",
            "raw_key": "wsk_secret",
            "key_hash": "hash_secret",
            "raw_tool_input": {"secret": "hidden"},
        }

    def issue_grant(
        self, *, agent_id: str, scopes: list[str], ttl_seconds: int
    ) -> dict[str, Any]:
        self.issued.append((agent_id, list(scopes), ttl_seconds))
        return {
            "grant_id": "grnt_issued",
            "grant_ref": "grt_issued",
            "workspace_id": "ws_main",
            "agent_id": agent_id,
            "scopes": list(scopes),
            "status": "active",
            "expires_at": "2999-06-11T12:00:00+00:00",
            "audit_event_id": "evt_issue",
            "raw_key": "wsk_secret",
            "key_hash": "hash_secret",
            "raw_tool_input": {"secret": "hidden"},
        }

    def create_boundary(
        self,
        *,
        name: str,
        runtime: str,
        boundary_type: str,
        mode: str,
    ) -> dict[str, Any]:
        self.created_boundaries.append((name, runtime, boundary_type, mode))
        return {
            "boundary_id": "bnd_created",
            "name": name,
            "runtime": runtime,
            "boundary_type": boundary_type,
            "mode": mode,
            "status": "active",
            "raw_key": "wsk_hidden",
        }

    def enable_boundary(self, boundary_id: str) -> dict[str, Any]:
        self.enabled_boundaries.append(boundary_id)
        return {**self.create_boundary(
            name="codex-local",
            runtime="codex",
            boundary_type="pretooluse",
            mode="fail_closed",
        ), "boundary_id": boundary_id}

    def disable_boundary(self, boundary_id: str) -> dict[str, Any]:
        self.disabled_boundaries.append(boundary_id)
        return {
            **self.enable_boundary(boundary_id),
            "status": "disabled",
        }

    def create_auto_approval_rule(
        self,
        *,
        name: str,
        target_agent_id: str,
        allowed_scopes: list[str],
        max_ttl_seconds: int,
    ) -> dict[str, Any]:
        self.created_rules.append(
            (name, target_agent_id, list(allowed_scopes), max_ttl_seconds)
        )
        return {
            "rule_id": "apr_created",
            "workspace_id": "ws_main",
            "name": name,
            "target_agent_id": target_agent_id,
            "allowed_scopes": list(allowed_scopes),
            "max_ttl_seconds": max_ttl_seconds,
            "status": "active",
            "created_by": "workspace:ws_main",
            "created_at": "2026-06-11T12:00:00+00:00",
            "updated_by": None,
            "updated_at": None,
            "key_hash": "hidden",
        }

    def disable_auto_approval_rule(self, rule_id: str) -> dict[str, Any]:
        self.disabled_rules.append(rule_id)
        return {
            **self.create_auto_approval_rule(
                name="CI",
                target_agent_id="agent_ci",
                allowed_scopes=["execute:ci/*"],
                max_ttl_seconds=900,
            ),
            "rule_id": rule_id,
            "status": "disabled",
            "updated_by": "workspace:ws_main",
        }


def test_approve_grant_request_proxies_client_and_returns_allowlisted_fields() -> None:
    client = FakeDecisionClient()
    tools = VinctorWriteTools(client)

    result = tools.approve_grant_request("grq_x", reason="looks safe")

    assert client.approved == [("grq_x", "looks safe")]
    assert result == {
        "request_id": "grq_x",
        "workspace_id": "ws_main",
        "requester_agent_id": "agent_release",
        "target_agent_id": "agent_release",
        "requested_ttl_seconds": 300,
        "status": "approved",
        "created_at": "2026-06-11T12:00:00+00:00",
        "decided_at": "2026-06-11T12:05:00+00:00",
        "decision_reason": "operator note",
        "issued_grant_ref": "grt_issued",
        "boundary_id": "bnd_main",
        "requester_runtime": "codex",
        "routing_hint": "manual_review_required",
        "routing_reason": "no_matching_auto_approval_rule",
        "queue_reason": "no_matching_auto_approval_rule",
        "audit_event_id": "evt_decision",
        "grant": {
            "grant_id": "grnt_issued",
            "grant_ref": "grt_issued",
            "workspace_id": "ws_main",
            "agent_id": "agent_release",
            "status": "active",
            "expires_at": "2999-06-11T12:00:00+00:00",
        },
    }


def test_reject_grant_request_proxies_client_and_returns_allowlisted_fields() -> None:
    client = FakeDecisionClient()
    tools = VinctorWriteTools(client)

    result = tools.reject_grant_request("grq_x", reason="out of policy")

    assert client.rejected == [("grq_x", "out of policy")]
    assert result["status"] == "rejected"
    assert result["audit_event_id"] == "evt_decision"


def test_auto_approve_grant_request_returns_allowlisted_evaluation() -> None:
    client = FakeDecisionClient()

    result = VinctorWriteTools(client).auto_approve_grant_request("grq_x")

    assert client.auto_approved == ["grq_x"]
    assert result["status"] == "approved"
    assert result["auto_approval"] == {
        "decision": "approved",
        "reason": "matched",
        "rule_id": "apr_main",
    }
    assert "raw_key" not in json.dumps(result)


def test_boundary_write_tools_proxy_and_allowlist_outputs() -> None:
    client = FakeDecisionClient()
    tools = VinctorWriteTools(client)

    created = tools.create_boundary(
        "codex-local", "codex", "pretooluse", "fail_closed"
    )
    enabled = tools.enable_boundary("bnd_x")
    disabled = tools.disable_boundary("bnd_x")

    assert client.created_boundaries[0] == (
        "codex-local",
        "codex",
        "pretooluse",
        "fail_closed",
    )
    assert enabled["boundary_id"] == "bnd_x"
    assert disabled["status"] == "disabled"
    assert "raw_key" not in json.dumps([created, enabled, disabled])


def test_auto_approval_rule_write_tools_proxy_and_follow_output_mode() -> None:
    client = FakeDecisionClient()
    safe_tools = VinctorWriteTools(client)
    diagnostic_tools = VinctorWriteTools(client, output_mode="diagnostic")

    created = safe_tools.create_auto_approval_rule(
        "CI", "agent_ci", ["execute:ci/*"], 900
    )
    disabled = diagnostic_tools.disable_auto_approval_rule("apr_x")

    assert client.created_rules[0] == ("CI", "agent_ci", ["execute:ci/*"], 900)
    assert created["created_by"] == "workspace:ws_main"
    assert "allowed_scopes" not in created
    assert disabled["status"] == "disabled"
    assert disabled["allowed_scopes"] == ["execute:ci/*"]
    assert "key_hash" not in json.dumps([created, disabled])


def test_revoke_grant_proxies_client_and_returns_allowlisted_fields() -> None:
    client = FakeDecisionClient()
    tools = VinctorWriteTools(client)

    result = tools.revoke_grant("grt_x")

    assert client.revoked == ["grt_x"]
    assert result == {
        "grant_id": "grnt_revoked",
        "grant_ref": "grt_x",
        "workspace_id": "ws_main",
        "agent_id": "agent_release",
        "status": "revoked",
        "expires_at": "2999-06-11T12:00:00+00:00",
        "audit_event_id": "evt_revoke",
    }


def test_revoke_grant_diagnostic_mode_includes_scope_fields() -> None:
    tools = VinctorWriteTools(FakeDecisionClient(), output_mode="diagnostic")

    result = tools.revoke_grant("grt_x")

    assert result["scopes"] == ["write:repo/feature/*"]


def test_revoke_grant_never_leaks_raw_keys_hashes_or_internals() -> None:
    tools = VinctorWriteTools(FakeDecisionClient(), output_mode="diagnostic")

    blob = json.dumps(tools.revoke_grant("grt_x"))

    for forbidden in ("wsk_", "hash_secret", "raw_tool_input", "raw_key"):
        assert forbidden not in blob


def test_issue_grant_proxies_client_and_returns_allowlisted_fields() -> None:
    client = FakeDecisionClient()
    tools = VinctorWriteTools(client)

    result = tools.issue_grant("aid", ["read:x/*"], 3600)

    assert client.issued == [("aid", ["read:x/*"], 3600)]
    assert result == {
        "grant_id": "grnt_issued",
        "grant_ref": "grt_issued",
        "workspace_id": "ws_main",
        "agent_id": "aid",
        "status": "active",
        "expires_at": "2999-06-11T12:00:00+00:00",
        "audit_event_id": "evt_issue",
    }


def test_issue_grant_diagnostic_mode_includes_scope_fields() -> None:
    tools = VinctorWriteTools(FakeDecisionClient(), output_mode="diagnostic")

    result = tools.issue_grant("aid", ["read:x/*"], 3600)

    assert result["scopes"] == ["read:x/*"]


def test_issue_grant_never_leaks_raw_keys_hashes_or_internals() -> None:
    tools = VinctorWriteTools(FakeDecisionClient(), output_mode="diagnostic")

    blob = json.dumps(tools.issue_grant("aid", ["read:x/*"], 3600))

    for forbidden in ("wsk_", "hash_secret", "raw_tool_input", "raw_key"):
        assert forbidden not in blob


def test_decision_diagnostic_mode_includes_scope_fields() -> None:
    tools = VinctorWriteTools(FakeDecisionClient(), output_mode="diagnostic")

    result = tools.approve_grant_request("grq_x", reason="ok")

    assert result["requested_scopes"] == ["write:repo/feature/*"]
    assert result["grant"]["scopes"] == ["write:repo/feature/*"]


def test_write_tools_never_leak_raw_keys_hashes_or_internals() -> None:
    tools = VinctorWriteTools(FakeDecisionClient(), output_mode="diagnostic")

    blob = json.dumps(
        [
            tools.approve_grant_request("grq_x", reason="ok"),
            tools.reject_grant_request("grq_x", reason="no"),
        ]
    )

    for forbidden in ("wsk_", "hash_secret", "raw_tool_input", "raw_key", "decided_by"):
        assert forbidden not in blob


def test_decision_omits_grant_when_service_returns_none() -> None:
    class NoGrantClient(FakeDecisionClient):
        def reject_grant_request(
            self,
            request_id: str,
            *,
            reason: str | None = None,
        ) -> dict[str, Any]:
            body = super().reject_grant_request(request_id, reason=reason)
            del body["grant"]
            return body

    tools = VinctorWriteTools(NoGrantClient())

    result = tools.reject_grant_request("grq_x", reason="no")

    assert "grant" not in result


def test_register_write_tools_adds_operator_mutations() -> None:
    mcp = FakeMcp()

    register_write_tools(mcp, FakeDecisionClient())

    assert sorted(mcp.tools) == [
        "vinctor_approve_grant_request",
        "vinctor_auto_approve_grant_request",
        "vinctor_create_auto_approval_rule",
        "vinctor_create_boundary",
        "vinctor_disable_auto_approval_rule",
        "vinctor_disable_boundary",
        "vinctor_enable_boundary",
        "vinctor_issue_grant",
        "vinctor_reject_grant_request",
        "vinctor_revoke_grant",
    ]


def test_write_tool_descriptions_state_operator_write_action() -> None:
    mcp = FakeMcp()

    register_write_tools(mcp, FakeDecisionClient())

    for name in ("vinctor_approve_grant_request", "vinctor_reject_grant_request"):
        description = mcp.descriptions[name]
        assert "operator" in description.lower()
        assert "audit" in description.lower()
        assert "own" in description.lower()


def test_revoke_tool_description_states_operator_write_action() -> None:
    mcp = FakeMcp()

    register_write_tools(mcp, FakeDecisionClient())

    description = mcp.descriptions["vinctor_revoke_grant"]
    assert "operator" in description.lower()
    assert "audit" in description.lower()


def test_issue_tool_description_states_operator_write_action() -> None:
    mcp = FakeMcp()

    register_write_tools(mcp, FakeDecisionClient())

    description = mcp.descriptions["vinctor_issue_grant"]
    assert "operator" in description.lower()
    assert "audit" in description.lower()
