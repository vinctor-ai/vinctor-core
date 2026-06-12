from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from vinctor_mcp_server.tools import VinctorReadOnlyTools, register_read_only_tools


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
    ) -> dict[str, Any]:
        self.seen_limits.append(limit)
        return super().list_audit_events(
            limit=limit,
            event_type=event_type,
            grant_ref=grant_ref,
            boundary_id=boundary_id,
            request_id=request_id,
            agent_id=agent_id,
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
    }
    assert "scope_attempted" not in event
    assert "scope_matched" not in event
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
        ) -> dict[str, Any]:
            self.seen_agent_id = agent_id
            return super().list_audit_events(
                limit=limit,
                event_type=event_type,
                grant_ref=grant_ref,
                boundary_id=boundary_id,
                request_id=request_id,
                agent_id=agent_id,
            )

    client = RecordingClient()
    tools = VinctorReadOnlyTools(client)

    tools.list_audit_events(agent_id="agent_release")

    assert client.seen_agent_id == "agent_release"


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
    assert "reason" not in request
    assert "task_id" not in request
    assert "session_id" not in request
    assert "repo" not in request
    assert "worktree" not in request
    assert "decided_by" not in request
    assert "raw_tool_input" not in request


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
        "created_at": "2026-06-11T12:00:00+00:00",
        "updated_at": None,
    }
    assert "allowed_scopes" not in rule
    assert "created_by" not in rule
    assert "updated_by" not in rule
    assert "raw_command" not in rule
    assert "key_hash" not in rule


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
        "vinctor_explain_denial",
        "vinctor_get_audit_event",
        "vinctor_get_boundary",
        "vinctor_get_grant",
        "vinctor_get_grant_request",
        "vinctor_list_audit_events",
        "vinctor_list_auto_approval_rules",
        "vinctor_list_boundaries",
        "vinctor_list_grant_requests",
        "vinctor_list_grants",
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
