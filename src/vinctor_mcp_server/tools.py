from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

from vinctor_core.scope import match_scope
from vinctor_mcp_server.output_policy import (
    AUDIT_EVENT_DIAGNOSTIC_FIELDS,
    AUDIT_EVENT_SAFE_FIELDS,
    AUTO_APPROVAL_RULE_DIAGNOSTIC_FIELDS,
    AUTO_APPROVAL_RULE_SAFE_FIELDS,
    BOUNDARY_FIELDS,
    GRANT_DIAGNOSTIC_FIELDS,
    GRANT_REQUEST_DIAGNOSTIC_FIELDS,
    GRANT_REQUEST_SAFE_FIELDS,
    GRANT_SAFE_FIELDS,
    STATUS_FIELDS,
    OutputMode,
    allowlist_object,
    fields_for_mode,
)


class ReadOnlyVinctorClient(Protocol):
    def status(self) -> dict[str, Any]: ...

    def list_boundaries(self) -> dict[str, Any]: ...

    def get_boundary(self, boundary_id: str) -> dict[str, Any]: ...

    def get_grant(self, grant_ref: str) -> dict[str, Any]: ...

    def list_grants(
        self,
        *,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]: ...

    def list_audit_events(
        self,
        *,
        limit: int = 20,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        request_id: str | None = None,
        agent_id: str | None = None,
    ) -> dict[str, Any]: ...

    def get_audit_event(self, event_id: str) -> dict[str, Any]: ...

    def list_grant_requests(self) -> dict[str, Any]: ...

    def get_grant_request(self, request_id: str) -> dict[str, Any]: ...

    def list_auto_approval_rules(self) -> dict[str, Any]: ...


class WriteVinctorClient(Protocol):
    def approve_grant_request(
        self,
        request_id: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]: ...

    def reject_grant_request(
        self,
        request_id: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]: ...

    def revoke_grant(self, grant_ref: str) -> dict[str, Any]: ...

    def issue_grant(
        self, *, agent_id: str, scopes: list[str], ttl_seconds: int
    ) -> dict[str, Any]: ...


class ToolRegistrar(Protocol):
    def tool(self, *, name: str, description: str) -> Any: ...


class VinctorReadOnlyTools:
    def __init__(
        self,
        client: ReadOnlyVinctorClient,
        *,
        output_mode: OutputMode = "safe",
    ) -> None:
        self._client = client
        self._output_mode = output_mode

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
        return allowlist_object(self._client.get_grant(grant_ref), self._grant_fields())

    def list_grants(
        self,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        body = self._client.list_grants(agent_id=agent_id, status=status)
        grants = body.get("grants", [])
        if not isinstance(grants, list):
            grants = []
        return {
            "grants": [
                allowlist_object(grant, self._grant_fields())
                for grant in grants
                if isinstance(grant, dict)
            ]
        }

    def list_audit_events(
        self,
        limit: int = 20,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        request_id: str | None = None,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        body = self._client.list_audit_events(
            limit=_clamp_audit_limit(limit),
            event_type=event_type,
            grant_ref=grant_ref,
            boundary_id=boundary_id,
            request_id=request_id,
            agent_id=agent_id,
        )
        events = body.get("audit_events", [])
        if not isinstance(events, list):
            events = []
        return {
            "audit_events": [
                allowlist_object(event, self._audit_fields())
                for event in events
                if isinstance(event, dict)
            ]
        }

    def get_audit_event(self, event_id: str) -> dict[str, Any]:
        return allowlist_object(self._client.get_audit_event(event_id), self._audit_fields())

    def list_grant_requests(self) -> dict[str, Any]:
        body = self._client.list_grant_requests()
        requests = body.get("grant_requests", [])
        if not isinstance(requests, list):
            requests = []
        return {
            "grant_requests": [
                allowlist_object(request, self._grant_request_fields())
                for request in requests
                if isinstance(request, dict)
            ]
        }

    def get_grant_request(self, request_id: str) -> dict[str, Any]:
        return allowlist_object(
            self._client.get_grant_request(request_id),
            self._grant_request_fields(),
        )

    def list_auto_approval_rules(self) -> dict[str, Any]:
        body = self._client.list_auto_approval_rules()
        rules = body.get("auto_approval_rules", [])
        if not isinstance(rules, list):
            rules = []
        return {
            "auto_approval_rules": [
                allowlist_object(rule, self._auto_approval_rule_fields())
                for rule in rules
                if isinstance(rule, dict)
            ]
        }

    def explain_denial(self, event_id: str) -> dict[str, Any]:
        event = self.get_audit_event(event_id)
        body = {
            "event_id": event.get("event_id"),
            "decision": event.get("decision"),
            "reason": event.get("reason"),
            "action": event.get("action"),
            "resource": event.get("resource"),
            "boundary_id": event.get("boundary_id"),
            "grant_ref": event.get("grant_ref"),
            "explanation": _denial_explanation(event),
        }
        if self._output_mode == "diagnostic":
            body.update(
                {
                    "scope_attempted": event.get("scope_attempted"),
                    "scope_matched": event.get("scope_matched"),
                    "missing_scope": _missing_scope(event),
                    "would_be_allowed_by": self._would_be_allowed_by(event),
                }
            )
        return body

    def _would_be_allowed_by(self, event: dict[str, Any]) -> list[str]:
        if self._output_mode != "diagnostic":
            return []
        if event.get("decision") != "deny":
            return []
        action = event.get("action")
        resource = event.get("resource")
        if not isinstance(action, str) or not isinstance(resource, str):
            return []
        agent_id = event.get("agent_id") if isinstance(event.get("agent_id"), str) else None
        grants = self.list_grants(agent_id=agent_id, status="active").get("grants", [])
        if not isinstance(grants, list):
            return []
        allowed_by: list[str] = []
        for grant in grants:
            if not isinstance(grant, dict) or not _active_unexpired_grant(grant):
                continue
            scopes = grant.get("scopes")
            grant_ref = grant.get("grant_ref")
            if (
                isinstance(scopes, list)
                and all(isinstance(scope, str) for scope in scopes)
                and isinstance(grant_ref, str)
                and match_scope(tuple(scopes), action, resource) is not None
            ):
                allowed_by.append(grant_ref)
        return allowed_by

    def _grant_fields(self) -> tuple[str, ...]:
        return fields_for_mode(
            GRANT_SAFE_FIELDS,
            GRANT_DIAGNOSTIC_FIELDS,
            self._output_mode,
        )

    def _audit_fields(self) -> tuple[str, ...]:
        return fields_for_mode(
            AUDIT_EVENT_SAFE_FIELDS,
            AUDIT_EVENT_DIAGNOSTIC_FIELDS,
            self._output_mode,
        )

    def _grant_request_fields(self) -> tuple[str, ...]:
        return fields_for_mode(
            GRANT_REQUEST_SAFE_FIELDS,
            GRANT_REQUEST_DIAGNOSTIC_FIELDS,
            self._output_mode,
        )

    def _auto_approval_rule_fields(self) -> tuple[str, ...]:
        return fields_for_mode(
            AUTO_APPROVAL_RULE_SAFE_FIELDS,
            AUTO_APPROVAL_RULE_DIAGNOSTIC_FIELDS,
            self._output_mode,
        )


def register_read_only_tools(
    mcp: ToolRegistrar,
    client: ReadOnlyVinctorClient,
    *,
    output_mode: OutputMode = "safe",
) -> VinctorReadOnlyTools:
    tools = VinctorReadOnlyTools(client, output_mode=output_mode)
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
        name="vinctor_list_grants",
        description=(
            "Read-only workspace grant lookup with optional agent_id and status filters. "
            "Does not issue or revoke grants."
        ),
    )(tools.list_grants)
    mcp.tool(
        name="vinctor_list_audit_events",
        description=(
            "Read-only Vinctor audit lookup with safe filters. Uses a 1..100 cap "
            "on limit. Output is model-visible and omits raw payloads, prompts, "
            "commands, keys, hashes, and service internals."
        ),
    )(tools.list_audit_events)
    mcp.tool(
        name="vinctor_get_audit_event",
        description=(
            "Read-only Vinctor audit event lookup by event_id. Output uses an allowlist."
        ),
    )(tools.get_audit_event)
    mcp.tool(
        name="vinctor_list_grant_requests",
        description=(
            "Read-only workspace grant request queue lookup. Does not approve, "
            "reject, auto-approve, issue, or revoke grants."
        ),
    )(tools.list_grant_requests)
    mcp.tool(
        name="vinctor_get_grant_request",
        description=(
            "Read-only grant request lookup by request_id. Does not decide the request."
        ),
    )(tools.get_grant_request)
    mcp.tool(
        name="vinctor_list_auto_approval_rules",
        description=(
            "Read-only auto-approval rule lookup. Does not create, disable, "
            "or evaluate rules."
        ),
    )(tools.list_auto_approval_rules)
    mcp.tool(
        name="vinctor_explain_denial",
        description=(
            "Explain a denied Vinctor audit event from service reason codes. "
            "Does not call /v1/enforce."
        ),
    )(tools.explain_denial)
    return tools


class VinctorWriteTools:
    def __init__(
        self,
        client: WriteVinctorClient,
        *,
        output_mode: OutputMode = "safe",
    ) -> None:
        self._client = client
        self._output_mode = output_mode

    def approve_grant_request(
        self,
        request_id: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return self._shape_decision(
            self._client.approve_grant_request(request_id, reason=reason)
        )

    def reject_grant_request(
        self,
        request_id: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return self._shape_decision(
            self._client.reject_grant_request(request_id, reason=reason)
        )

    def revoke_grant(self, grant_ref: str) -> dict[str, Any]:
        body = self._client.revoke_grant(grant_ref)
        return {
            **allowlist_object(body, self._grant_fields()),
            "audit_event_id": body.get("audit_event_id"),
        }

    def issue_grant(
        self, agent_id: str, scopes: list[str], ttl_seconds: int
    ) -> dict[str, Any]:
        body = self._client.issue_grant(
            agent_id=agent_id, scopes=scopes, ttl_seconds=ttl_seconds
        )
        return {
            **allowlist_object(body, self._grant_fields()),
            "audit_event_id": body.get("audit_event_id"),
        }

    def _shape_decision(self, body: dict[str, Any]) -> dict[str, Any]:
        shaped: dict[str, Any] = {
            **allowlist_object(body, self._grant_request_fields()),
            "audit_event_id": body.get("audit_event_id"),
        }
        grant = body.get("grant")
        if isinstance(grant, dict):
            shaped["grant"] = allowlist_object(grant, self._grant_fields())
        return shaped

    def _grant_request_fields(self) -> tuple[str, ...]:
        return fields_for_mode(
            GRANT_REQUEST_SAFE_FIELDS,
            GRANT_REQUEST_DIAGNOSTIC_FIELDS,
            self._output_mode,
        )

    def _grant_fields(self) -> tuple[str, ...]:
        return fields_for_mode(
            GRANT_SAFE_FIELDS,
            GRANT_DIAGNOSTIC_FIELDS,
            self._output_mode,
        )


def register_write_tools(
    mcp: ToolRegistrar,
    client: WriteVinctorClient,
    *,
    output_mode: OutputMode = "safe",
) -> VinctorWriteTools:
    tools = VinctorWriteTools(client, output_mode=output_mode)
    mcp.tool(
        name="vinctor_approve_grant_request",
        description=(
            "Operator write action: approve a pending grant request by request_id "
            "via the workspace-key authorized operator endpoint. The service "
            "authenticates, audits the decision (returns audit_event_id), and "
            "prevents execution agents from approving their own requests. Output "
            "is allowlist-shaped and omits raw keys, hashes, and service internals."
        ),
    )(tools.approve_grant_request)
    mcp.tool(
        name="vinctor_reject_grant_request",
        description=(
            "Operator write action: reject a pending grant request by request_id "
            "via the workspace-key authorized operator endpoint. The service "
            "authenticates, audits the decision (returns audit_event_id), and "
            "prevents execution agents from deciding their own requests. Output "
            "is allowlist-shaped and omits raw keys, hashes, and service internals."
        ),
    )(tools.reject_grant_request)
    mcp.tool(
        name="vinctor_revoke_grant",
        description=(
            "Operator write action: revoke an active grant by grant_ref via the "
            "workspace-key authorized operator endpoint. The service authenticates "
            "and audits the revocation (returns audit_event_id); the MCP server "
            "issues nothing. Output is allowlist-shaped and omits raw keys, hashes, "
            "and service internals."
        ),
    )(tools.revoke_grant)
    mcp.tool(
        name="vinctor_issue_grant",
        description=(
            "Operator write action: issue a grant for an agent (agent_id, scopes, "
            "ttl_seconds) via the workspace-key authorized operator endpoint. The "
            "service authenticates, enforces the workspace's issuable-scope bounds "
            "and max TTL, and audits the issuance (returns audit_event_id); the MCP "
            "server mints nothing. Output is allowlist-shaped and omits raw keys, "
            "hashes, and service internals."
        ),
    )(tools.issue_grant)
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


def _missing_scope(event: dict[str, Any]) -> str | None:
    if event.get("decision") != "deny" or event.get("scope_matched") is not None:
        return None
    scope_attempted = event.get("scope_attempted")
    if isinstance(scope_attempted, str):
        return scope_attempted
    return None


def _active_unexpired_grant(grant: dict[str, Any]) -> bool:
    if grant.get("status") != "active":
        return False
    expires_at = grant.get("expires_at")
    if expires_at is None:
        return True
    if not isinstance(expires_at, str):
        return False
    try:
        expiry = datetime.fromisoformat(expires_at)
    except ValueError:
        return False
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    return expiry > datetime.now(UTC)


def _clamp_audit_limit(limit: int) -> int:
    return max(1, min(limit, 100))
