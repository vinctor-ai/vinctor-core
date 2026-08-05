from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from vinctor_core.audit import validate_audit_event_class
from vinctor_core.scope import match_scope
from vinctor_mcp_server.output_policy import (
    AUDIT_EVENT_DIAGNOSTIC_FIELDS,
    AUDIT_EVENT_SAFE_FIELDS,
    AUTO_APPROVAL_EVALUATION_FIELDS,
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

_GRANT_LIFECYCLE_EVENT_TYPES = frozenset({"grant_issued", "grant_revoked"})


class _AuditPaginationError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _AuditReportEvent:
    payload: dict[str, Any]
    event_id: str
    event_type: str
    event_class: str
    decision: str
    workspace_id: str
    agent_id: str
    grant_id: str
    grant_ref: str
    boundary_id: str | None
    created_at: datetime
    sequence: int


@dataclass(frozen=True, slots=True)
class _AuditReportPage:
    events: tuple[_AuditReportEvent, ...]
    snapshot_event_id: str | None
    next_before_event_id: str | None


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
        event_class: str | None = None,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        request_id: str | None = None,
        agent_id: str | None = None,
        reason_code: str | None = None,
        enforcing_principal: str | None = None,
        subject_token_verified: bool | None = None,
        paginate: bool = False,
        snapshot_event_id: str | None = None,
        before_event_id: str | None = None,
    ) -> dict[str, Any]: ...

    def get_audit_event(self, event_id: str) -> dict[str, Any]: ...

    def list_grant_requests(self) -> dict[str, Any]: ...

    def get_grant_request(self, request_id: str) -> dict[str, Any]: ...

    def list_auto_approval_rules(self) -> dict[str, Any]: ...

    def list_service_auth_failures(self, *, limit: int = 20) -> dict[str, Any]: ...


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

    def auto_approve_grant_request(self, request_id: str) -> dict[str, Any]: ...

    def revoke_grant(self, grant_ref: str) -> dict[str, Any]: ...

    def issue_grant(
        self, *, agent_id: str, scopes: list[str], ttl_seconds: int
    ) -> dict[str, Any]: ...

    def create_boundary(
        self,
        *,
        name: str,
        runtime: str,
        boundary_type: str,
        mode: str,
    ) -> dict[str, Any]: ...

    def enable_boundary(self, boundary_id: str) -> dict[str, Any]: ...

    def disable_boundary(self, boundary_id: str) -> dict[str, Any]: ...

    def create_auto_approval_rule(
        self,
        *,
        name: str,
        target_agent_id: str,
        allowed_scopes: list[str],
        max_ttl_seconds: int,
    ) -> dict[str, Any]: ...

    def disable_auto_approval_rule(self, rule_id: str) -> dict[str, Any]: ...


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
        event_class: str | None = None,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        request_id: str | None = None,
        agent_id: str | None = None,
        reason_code: str | None = None,
        enforcing_principal: str | None = None,
        subject_token_verified: bool | None = None,
    ) -> dict[str, Any]:
        validate_audit_event_class(event_class)
        body = self._client.list_audit_events(
            limit=_clamp_audit_limit(limit),
            event_class=event_class,
            event_type=event_type,
            grant_ref=grant_ref,
            boundary_id=boundary_id,
            request_id=request_id,
            agent_id=agent_id,
            reason_code=reason_code,
            enforcing_principal=enforcing_principal,
            subject_token_verified=subject_token_verified,
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

    def list_grant_requests(self, status: str | None = None) -> dict[str, Any]:
        body = self._client.list_grant_requests()
        requests = body.get("grant_requests", [])
        if not isinstance(requests, list):
            requests = []
        if status is not None:
            requests = [
                request
                for request in requests
                if isinstance(request, dict) and request.get("status") == status
            ]
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

    def list_service_auth_failures(self, limit: int = 20) -> dict[str, Any]:
        body = self._client.list_service_auth_failures(
            limit=_clamp_auth_failure_limit(limit)
        )
        events = body.get("auth_failures", [])
        if not isinstance(events, list):
            events = []
        return {
            "auth_failures": [
                allowlist_object(event, self._audit_fields())
                for event in events
                if isinstance(event, dict)
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

    def grant_report(self, grant_ref: str) -> dict[str, Any]:
        grant = self.get_grant(grant_ref)
        events = self._complete_audit_events(grant_ref=grant_ref)
        lifecycle = [
            event.payload
            for event in events
            if event.event_type in _GRANT_LIFECYCLE_EVENT_TYPES
        ]
        usage = [
            event.payload
            for event in events
            if event.event_type not in _GRANT_LIFECYCLE_EVENT_TYPES
        ]
        return {"grant": grant, "lifecycle": lifecycle, "usage": usage}

    def boundary_report(self, boundary_id: str) -> dict[str, Any]:
        boundary = self.get_boundary(boundary_id)
        events = self._complete_audit_events(boundary_id=boundary_id)
        # ADR 0019: control-plane mutations share the chain, permit-encoded.
        # Agent activity counts decision-class events only; mutations are
        # reported separately, never folded into permits.
        decision_events = [event for event in events if event.event_class == "decision"]
        control_events = [event for event in events if event.event_class == "control"]
        permit = sum(1 for event in decision_events if event.decision == "permit")
        deny = sum(1 for event in decision_events if event.decision == "deny")
        return {
            "boundary": boundary,
            "activity": {"permit": permit, "deny": deny},
            "control_changes": {
                "count": len(control_events),
                "timeline": [event.payload for event in control_events],
            },
            "recent": [event.payload for event in events],
        }

    def grant_request_report(self, request_id: str) -> dict[str, Any]:
        request = self.get_grant_request(request_id)
        timeline = self._complete_audit_events(request_id=request_id)
        report: dict[str, Any] = {
            "grant_request": request,
            "timeline": [event.payload for event in timeline],
        }
        grant_ref = request.get("issued_grant_ref")
        if isinstance(grant_ref, str) and grant_ref:
            report["grant"] = self.get_grant(grant_ref)
            grant_events = self._complete_audit_events(grant_ref=grant_ref)
            report["timeline"] = [
                event.payload
                for event in _merge_audit_event_streams(timeline, grant_events)
            ]
        return report

    def _complete_audit_events(
        self,
        *,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        request_id: str | None = None,
    ) -> list[_AuditReportEvent]:
        pages: list[tuple[_AuditReportEvent, ...]] = []
        snapshot_event_id: str | None = None
        before_event_id: str | None = None
        seen_cursors: set[str] = set()
        seen_event_ids: set[str] = set()
        while True:
            body = self._client.list_audit_events(
                limit=100,
                grant_ref=grant_ref,
                boundary_id=boundary_id,
                request_id=request_id,
                paginate=True,
                snapshot_event_id=snapshot_event_id,
                before_event_id=before_event_id,
            )
            page = _parse_audit_report_page(body, self._audit_fields())
            page_events = page.events
            if before_event_id is not None and not page_events:
                raise _AuditPaginationError("service returned an empty audit continuation page")
            for event in page_events:
                if event.event_id in seen_event_ids:
                    raise _AuditPaginationError(
                        "service returned a duplicate audit event"
                    )
                seen_event_ids.add(event.event_id)
            raw_snapshot = page.snapshot_event_id
            next_before = page.next_before_event_id
            if snapshot_event_id is None:
                if not page_events and raw_snapshot is not None:
                    raise _AuditPaginationError(
                        "service returned an incoherent audit snapshot cursor"
                    )
                if page_events and raw_snapshot != page_events[-1].event_id:
                    raise _AuditPaginationError(
                        "service returned an incoherent audit snapshot cursor"
                    )
                snapshot_event_id = raw_snapshot
            elif raw_snapshot != snapshot_event_id:
                raise _AuditPaginationError("service changed the audit snapshot cursor")
            if next_before is None:
                pages.append(page_events)
                break
            if (
                not isinstance(next_before, str)
                or next_before == ""
                or snapshot_event_id is None
                or next_before in seen_cursors
                or not page_events
                or page_events[0].event_id != next_before
            ):
                raise _AuditPaginationError("service returned an invalid audit page cursor")
            pages.append(page_events)
            seen_cursors.add(next_before)
            before_event_id = next_before
        complete = [
            event
            for page_events in reversed(pages)
            for event in page_events
        ]
        if any(
            previous.sequence >= current.sequence
            for previous, current in zip(complete, complete[1:], strict=False)
        ):
            raise _AuditPaginationError(
                "service returned inconsistent audit chronology"
            )
        return complete

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
            "Read-only Vinctor audit lookup with safe filters, including event_class "
            "(control or decision). Uses a 1..100 cap on limit. Output is model-visible "
            "and omits raw payloads, prompts, commands, keys, hashes, and service "
            "internals."
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
            "Read-only workspace grant request queue lookup with an optional "
            "status filter. Does not approve, reject, auto-approve, issue, or "
            "revoke grants."
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
        name="vinctor_list_service_auth_failures",
        description=(
            "Read-only global authentication-failure audit lookup using the "
            "dedicated service-operator credential. Uses a 1..200 cap on limit; "
            "output is allowlist-shaped and omits credentials and raw payloads."
        ),
    )(tools.list_service_auth_failures)
    mcp.tool(
        name="vinctor_explain_denial",
        description=(
            "Explain a denied Vinctor audit event from service reason codes. "
            "Does not call /v1/enforce."
        ),
    )(tools.explain_denial)
    mcp.tool(
        name="vinctor_grant_report",
        description=(
            "Inspect a grant's authorization state: returns the grant (status, "
            "expiry) plus its audit timeline partitioned into lifecycle "
            "(issued/revoked) and usage (enforcement decisions). Read-only; output "
            "is allowlist-shaped and omits raw keys, hashes, and service internals."
        ),
    )(tools.grant_report)
    mcp.tool(
        name="vinctor_boundary_report",
        description=(
            "Inspect a boundary's authorization activity: returns the boundary plus "
            "a permit/deny summary of agent decisions, a separate control-mutation "
            "timeline (registration/status changes), and recent audit events for it. "
            "Read-only; output is allowlist-shaped and omits raw keys, hashes, and "
            "service internals."
        ),
    )(tools.boundary_report)
    mcp.tool(
        name="vinctor_grant_request_report",
        description=(
            "Inspect a grant request and its correlated audit timeline, including "
            "the issued grant and grant audit events when present. Read-only; "
            "output is allowlist-shaped and omits raw keys, hashes, and service "
            "internals."
        ),
    )(tools.grant_request_report)
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

    def auto_approve_grant_request(self, request_id: str) -> dict[str, Any]:
        body = self._client.auto_approve_grant_request(request_id)
        shaped = self._shape_decision(body)
        evaluation = body.get("auto_approval")
        if isinstance(evaluation, dict):
            shaped["auto_approval"] = allowlist_object(
                evaluation,
                AUTO_APPROVAL_EVALUATION_FIELDS,
            )
        return shaped

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

    def create_boundary(
        self,
        name: str,
        runtime: str,
        boundary_type: str,
        mode: str,
    ) -> dict[str, Any]:
        return allowlist_object(
            self._client.create_boundary(
                name=name,
                runtime=runtime,
                boundary_type=boundary_type,
                mode=mode,
            ),
            BOUNDARY_FIELDS,
        )

    def enable_boundary(self, boundary_id: str) -> dict[str, Any]:
        return allowlist_object(
            self._client.enable_boundary(boundary_id),
            BOUNDARY_FIELDS,
        )

    def disable_boundary(self, boundary_id: str) -> dict[str, Any]:
        return allowlist_object(
            self._client.disable_boundary(boundary_id),
            BOUNDARY_FIELDS,
        )

    def create_auto_approval_rule(
        self,
        name: str,
        target_agent_id: str,
        allowed_scopes: list[str],
        max_ttl_seconds: int,
    ) -> dict[str, Any]:
        return allowlist_object(
            self._client.create_auto_approval_rule(
                name=name,
                target_agent_id=target_agent_id,
                allowed_scopes=allowed_scopes,
                max_ttl_seconds=max_ttl_seconds,
            ),
            self._auto_approval_rule_fields(),
        )

    def disable_auto_approval_rule(self, rule_id: str) -> dict[str, Any]:
        return allowlist_object(
            self._client.disable_auto_approval_rule(rule_id),
            self._auto_approval_rule_fields(),
        )

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

    def _auto_approval_rule_fields(self) -> tuple[str, ...]:
        return fields_for_mode(
            AUTO_APPROVAL_RULE_SAFE_FIELDS,
            AUTO_APPROVAL_RULE_DIAGNOSTIC_FIELDS,
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
        name="vinctor_auto_approve_grant_request",
        description=(
            "Operator write action: evaluate and auto-approve a pending grant "
            "request by request_id via active workspace rules. The service "
            "authenticates, enforces rule and issuable-scope bounds, and audits "
            "successful issuance. Output is allowlist-shaped."
        ),
    )(tools.auto_approve_grant_request)
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
    mcp.tool(
        name="vinctor_create_boundary",
        description=(
            "Operator write action: create a runtime boundary via the "
            "workspace-key authorized endpoint. Output is allowlist-shaped."
        ),
    )(tools.create_boundary)
    mcp.tool(
        name="vinctor_enable_boundary",
        description=(
            "Operator write action: enable a boundary by boundary_id via the "
            "workspace-key authorized endpoint. Output is allowlist-shaped."
        ),
    )(tools.enable_boundary)
    mcp.tool(
        name="vinctor_disable_boundary",
        description=(
            "Operator write action: disable a boundary by boundary_id via the "
            "workspace-key authorized endpoint. Output is allowlist-shaped."
        ),
    )(tools.disable_boundary)
    mcp.tool(
        name="vinctor_create_auto_approval_rule",
        description=(
            "Operator write action: create an auto-approval rule via the "
            "workspace-key authorized endpoint. Output is allowlist-shaped and "
            "scope detail follows the configured output mode."
        ),
    )(tools.create_auto_approval_rule)
    mcp.tool(
        name="vinctor_disable_auto_approval_rule",
        description=(
            "Operator write action: disable an auto-approval rule by rule_id via "
            "the workspace-key authorized endpoint. Output is allowlist-shaped."
        ),
    )(tools.disable_auto_approval_rule)
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


def _event_class(event: dict[str, Any]) -> str:
    # Rows written before event_class existed omit the field and are
    # decision-class by definition (AuditEvent.to_dict omits "event_class"
    # when it is "decision", so an absent field means a decision row).
    value = event.get("event_class")
    return value if isinstance(value, str) else "decision"


def _clamp_audit_limit(limit: int) -> int:
    return max(1, min(limit, 100))


def _clamp_auth_failure_limit(limit: int) -> int:
    return max(1, min(limit, 200))


def _parse_audit_report_page(
    body: dict[str, Any],
    fields: tuple[str, ...],
) -> _AuditReportPage:
    if not isinstance(body, dict) or "audit_events" not in body:
        raise _AuditPaginationError("service returned invalid audit events")
    raw_events = body["audit_events"]
    if not isinstance(raw_events, list):
        raise _AuditPaginationError("service returned invalid audit events")
    events = tuple(
        _parse_audit_report_event(raw_event, fields)
        for raw_event in raw_events
    )

    if "page" not in body or not isinstance(body["page"], dict):
        raise _AuditPaginationError("service omitted audit pagination metadata")
    page = body["page"]
    if "snapshot_event_id" not in page or "next_before_event_id" not in page:
        raise _AuditPaginationError("service omitted audit pagination metadata")
    snapshot_event_id = _parse_audit_cursor(page["snapshot_event_id"])
    next_before_event_id = _parse_audit_cursor(page["next_before_event_id"])
    return _AuditReportPage(
        events=events,
        snapshot_event_id=snapshot_event_id,
        next_before_event_id=next_before_event_id,
    )


def _parse_audit_report_event(
    raw_event: object,
    fields: tuple[str, ...],
) -> _AuditReportEvent:
    if not isinstance(raw_event, dict):
        raise _AuditPaginationError("service returned invalid audit events")

    event_id = _required_audit_string(raw_event, "event_id", nonempty=True)
    event_type = _required_audit_string(raw_event, "event_type", nonempty=True)
    event_class = _required_audit_string(raw_event, "event_class", nonempty=True)
    if event_class not in {"control", "decision"}:
        raise _AuditPaginationError("service returned invalid audit events")
    decision = _required_audit_string(raw_event, "decision", nonempty=True)
    if decision not in {"permit", "deny"}:
        raise _AuditPaginationError("service returned invalid audit events")
    workspace_id = _required_audit_string(raw_event, "workspace_id")
    agent_id = _required_audit_string(raw_event, "agent_id")
    grant_id = _required_audit_string(raw_event, "grant_id")
    grant_ref = _required_audit_string(raw_event, "grant_ref")
    boundary_id = raw_event.get("boundary_id")
    if boundary_id is not None and not isinstance(boundary_id, str):
        raise _AuditPaginationError("service returned invalid audit events")
    created_at_text = _required_audit_string(raw_event, "created_at", nonempty=True)
    try:
        created_at = datetime.fromisoformat(created_at_text)
    except ValueError as exc:
        raise _AuditPaginationError("service returned invalid audit events") from exc
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise _AuditPaginationError("service returned invalid audit events")
    sequence = raw_event.get("sequence")
    if type(sequence) is not int or sequence < 1:
        raise _AuditPaginationError("service returned invalid audit events")

    return _AuditReportEvent(
        payload=allowlist_object(raw_event, fields),
        event_id=event_id,
        event_type=event_type,
        event_class=event_class,
        decision=decision,
        workspace_id=workspace_id,
        agent_id=agent_id,
        grant_id=grant_id,
        grant_ref=grant_ref,
        boundary_id=boundary_id,
        created_at=created_at.astimezone(UTC),
        sequence=sequence,
    )


def _required_audit_string(
    event: dict[str, Any],
    field: str,
    *,
    nonempty: bool = False,
) -> str:
    value = event.get(field)
    if not isinstance(value, str) or (nonempty and value == ""):
        raise _AuditPaginationError("service returned invalid audit events")
    return value


def _parse_audit_cursor(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str or value == "":
        raise _AuditPaginationError("service returned an invalid audit page cursor")
    return value


def _merge_audit_event_streams(
    *streams: list[_AuditReportEvent],
) -> list[_AuditReportEvent]:
    events_by_id: dict[str, _AuditReportEvent] = {}
    event_ids_by_sequence: dict[int, str] = {}

    for stream in streams:
        for event in stream:
            existing = events_by_id.get(event.event_id)
            if existing is not None and existing != event:
                raise _AuditPaginationError(
                    "service returned inconsistent overlapping audit events"
                )
            event_id_at_sequence = event_ids_by_sequence.get(event.sequence)
            if (
                event_id_at_sequence is not None
                and event_id_at_sequence != event.event_id
            ):
                raise _AuditPaginationError(
                    "service returned inconsistent audit chronology"
                )
            events_by_id[event.event_id] = event
            event_ids_by_sequence[event.sequence] = event.event_id

    return sorted(events_by_id.values(), key=lambda event: event.sequence)
