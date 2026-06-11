from __future__ import annotations

from typing import Any, Protocol

from vinctor_mcp_server.output_policy import (
    AUDIT_EVENT_FIELDS,
    BOUNDARY_FIELDS,
    GRANT_FIELDS,
    STATUS_FIELDS,
    allowlist_object,
)


class ReadOnlyVinctorClient(Protocol):
    def status(self) -> dict[str, Any]: ...

    def list_boundaries(self) -> dict[str, Any]: ...

    def get_boundary(self, boundary_id: str) -> dict[str, Any]: ...

    def get_grant(self, grant_ref: str) -> dict[str, Any]: ...

    def list_audit_events(
        self,
        *,
        limit: int = 20,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]: ...

    def get_audit_event(self, event_id: str) -> dict[str, Any]: ...


class ToolRegistrar(Protocol):
    def tool(self, *, name: str, description: str) -> Any: ...


class VinctorReadOnlyTools:
    def __init__(self, client: ReadOnlyVinctorClient) -> None:
        self._client = client

    def status(self) -> dict[str, Any]:
        return allowlist_object(self._client.status(), STATUS_FIELDS)

    def list_boundaries(self) -> dict[str, Any]:
        body = self._client.list_boundaries()
        boundaries = body.get("boundaries", [])
        if not isinstance(boundaries, list):
            boundaries = []
        return {
            "boundaries": [
                allowlist_object(boundary, BOUNDARY_FIELDS)
                for boundary in boundaries
                if isinstance(boundary, dict)
            ]
        }

    def get_boundary(self, boundary_id: str) -> dict[str, Any]:
        return allowlist_object(self._client.get_boundary(boundary_id), BOUNDARY_FIELDS)

    def get_grant(self, grant_ref: str) -> dict[str, Any]:
        return allowlist_object(self._client.get_grant(grant_ref), GRANT_FIELDS)

    def list_audit_events(
        self,
        limit: int = 20,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        body = self._client.list_audit_events(
            limit=limit,
            event_type=event_type,
            grant_ref=grant_ref,
            boundary_id=boundary_id,
            request_id=request_id,
        )
        events = body.get("audit_events", [])
        if not isinstance(events, list):
            events = []
        return {
            "audit_events": [
                allowlist_object(event, AUDIT_EVENT_FIELDS)
                for event in events
                if isinstance(event, dict)
            ]
        }

    def get_audit_event(self, event_id: str) -> dict[str, Any]:
        return allowlist_object(self._client.get_audit_event(event_id), AUDIT_EVENT_FIELDS)

    def explain_denial(self, audit_event_id: str) -> dict[str, Any]:
        event = self.get_audit_event(audit_event_id)
        return {
            "event_id": event.get("event_id"),
            "decision": event.get("decision"),
            "reason": event.get("reason"),
            "action": event.get("action"),
            "resource": event.get("resource"),
            "scope_attempted": event.get("scope_attempted"),
            "scope_matched": event.get("scope_matched"),
            "boundary_id": event.get("boundary_id"),
            "grant_ref": event.get("grant_ref"),
            "explanation": _denial_explanation(event),
        }


def register_read_only_tools(
    mcp: ToolRegistrar,
    client: ReadOnlyVinctorClient,
) -> VinctorReadOnlyTools:
    tools = VinctorReadOnlyTools(client)
    mcp.tool(
        name="vinctor_status",
        description=(
            "Read-only Vinctor service status. Output is model-visible and limited "
            "to safe status fields."
        ),
    )(tools.status)
    mcp.tool(
        name="vinctor_list_boundaries",
        description=(
            "Read-only list of Vinctor runtime boundaries. Does not call /v1/enforce."
        ),
    )(tools.list_boundaries)
    mcp.tool(
        name="vinctor_get_boundary",
        description=(
            "Read-only Vinctor boundary lookup by boundary_id. Does not execute actions."
        ),
    )(tools.get_boundary)
    mcp.tool(
        name="vinctor_get_grant",
        description=(
            "Read-only Vinctor grant lookup by grant_ref. Does not issue or revoke grants."
        ),
    )(tools.get_grant)
    mcp.tool(
        name="vinctor_list_audit_events",
        description=(
            "Read-only Vinctor audit lookup with safe filters. Output is model-visible "
            "and omits raw payloads, prompts, commands, keys, hashes, and service internals."
        ),
    )(tools.list_audit_events)
    mcp.tool(
        name="vinctor_get_audit_event",
        description=(
            "Read-only Vinctor audit event lookup by event_id. Output uses an allowlist."
        ),
    )(tools.get_audit_event)
    mcp.tool(
        name="vinctor_explain_denial",
        description=(
            "Explain a denied Vinctor audit event from service reason codes. "
            "Does not call /v1/enforce."
        ),
    )(tools.explain_denial)
    return tools


def _denial_explanation(event: dict[str, Any]) -> str:
    if event.get("decision") != "deny":
        return "This audit event is not a denial."
    reason = event.get("reason")
    explanations = {
        "action_denied": (
            "Vinctor denied the request because the issued grant did not permit "
            "the requested action/resource."
        ),
        "boundary_inactive": "Vinctor denied the request because the boundary is disabled.",
        "boundary_not_found": "Vinctor denied the request because the boundary was not found.",
        "grant_expired": "Vinctor denied the request because the grant has expired.",
        "grant_revoked": "Vinctor denied the request because the grant has been revoked.",
        "invalid_action": "Vinctor denied the request because the action was invalid.",
        "invalid_resource": "Vinctor denied the request because the resource was invalid.",
        "invalid_grant_scope": "Vinctor denied the request because the grant scope was invalid.",
        "no_applicable_grant": (
            "Vinctor denied the request because no applicable issued grant matched."
        ),
    }
    if isinstance(reason, str):
        return explanations.get(reason, f"Vinctor denied the request with reason code {reason}.")
    return "Vinctor denied the request."
