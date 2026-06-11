from __future__ import annotations

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

    def list_audit_events(
        self,
        *,
        limit: int = 20,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        request_id: str | None = None,
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
        "scopes": ["write:repo/feature/*"],
        "status": "active",
        "expires_at": "2026-06-11T12:00:00+00:00",
    }


def test_audit_tools_return_allowlisted_fields() -> None:
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
        "scope_attempted": "send:email/external",
        "scope_matched": None,
        "boundary_id": None,
        "runtime": None,
        "boundary_type": None,
        "created_at": "2026-06-11T12:00:00+00:00",
    }
    assert "event_json" not in event
    assert "raw_command" not in event
    assert "key_hash" not in event

    fetched = tools.get_audit_event("evt_deny")
    assert fetched["event_id"] == "evt_deny"
    assert "raw_tool_input" not in fetched


def test_explain_denial_uses_reason_code_without_raw_payloads() -> None:
    tools = VinctorReadOnlyTools(FakeClient())

    explanation = tools.explain_denial("evt_deny")

    assert explanation == {
        "event_id": "evt_deny",
        "decision": "deny",
        "reason": "action_denied",
        "action": "send",
        "resource": "email/external",
        "scope_attempted": "send:email/external",
        "scope_matched": None,
        "boundary_id": "bnd_main",
        "grant_ref": "grt_main",
        "explanation": (
            "Vinctor denied the request because the issued grant did not permit "
            "the requested action/resource."
        ),
    }
    assert "raw_tool_input" not in explanation


def test_registers_only_read_only_mvp_tools() -> None:
    mcp = FakeMcp()

    register_read_only_tools(mcp, FakeClient())

    assert sorted(mcp.tools) == [
        "vinctor_explain_denial",
        "vinctor_get_audit_event",
        "vinctor_get_boundary",
        "vinctor_get_grant",
        "vinctor_list_audit_events",
        "vinctor_list_boundaries",
        "vinctor_status",
    ]
    assert not any("approve" in name for name in mcp.tools)
    assert not any("reject" in name for name in mcp.tools)
    assert not any("revoke" in name for name in mcp.tools)
    assert not any("issue" in name for name in mcp.tools)
