from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from secrets import token_urlsafe
from typing import Protocol

from vinctor_service.boundary_http import WorkspaceIdentity
from vinctor_service.models import AutoApprovalRule
from vinctor_service.v1_http import V1HttpResponse


class AutoApprovalAdminService(Protocol):
    def create_auto_approval_rule(self, rule: AutoApprovalRule) -> AutoApprovalRule: ...

    def list_auto_approval_rules(
        self,
        *,
        workspace_id: str,
    ) -> tuple[AutoApprovalRule, ...]: ...

    def disable_auto_approval_rule(
        self,
        *,
        rule_id: str,
        workspace_id: str,
        disabled_by: str,
        now: datetime,
    ) -> AutoApprovalRule | None: ...


WorkspaceIdentityResolver = Callable[[str, datetime], WorkspaceIdentity | None]


@dataclass(frozen=True)
class ParsedCreateRuleBody:
    name: str
    target_agent_id: str
    allowed_scopes: tuple[str, ...]
    max_ttl_seconds: int


def handle_v1_auto_approval_rules_http(
    *,
    method: str,
    path: str,
    headers: Mapping[str, str],
    body: object,
    workspace_identities: Mapping[str, WorkspaceIdentity] | None = None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None = None,
    service: AutoApprovalAdminService,
    now: datetime,
) -> V1HttpResponse:
    identity = _workspace_identity(
        headers,
        workspace_identities=workspace_identities,
        workspace_identity_resolver=workspace_identity_resolver,
        now=now,
    )
    if identity is None:
        return _error(401, "authentication_required", "valid X-Workspace-Key header is required")

    if path == "/v1/auto-approval-rules":
        if method == "POST":
            return _create_rule(body, identity=identity, service=service, now=now)
        if method == "GET":
            return V1HttpResponse(
                status_code=200,
                body={
                    "auto_approval_rules": [
                        _rule_body(rule)
                        for rule in service.list_auto_approval_rules(
                            workspace_id=identity.workspace_id
                        )
                    ]
                },
            )
        return _error(
            405,
            "method_not_allowed",
            "GET or POST is required for /v1/auto-approval-rules",
        )

    prefix = "/v1/auto-approval-rules/"
    if path.startswith(prefix):
        suffix = path.removeprefix(prefix)
        parts = suffix.split("/")
        if len(parts) == 2 and parts[0] != "" and parts[1] == "disable":
            if method != "POST":
                return _error(
                    405,
                    "method_not_allowed",
                    "POST is required for /v1/auto-approval-rules/{rule_id}/disable",
                )
            disabled = service.disable_auto_approval_rule(
                rule_id=parts[0],
                workspace_id=identity.workspace_id,
                disabled_by=f"workspace:{identity.workspace_id}",
                now=now,
            )
            if disabled is None:
                return _error(
                    404,
                    "auto_approval_rule_not_found",
                    "auto-approval rule was not found",
                )
            return V1HttpResponse(status_code=200, body=_rule_body(disabled))

        if suffix == "" or "/" in suffix:
            return _error(404, "not_found", "route not found")

    return _error(404, "not_found", "route not found")


def _create_rule(
    body: object,
    *,
    identity: WorkspaceIdentity,
    service: AutoApprovalAdminService,
    now: datetime,
) -> V1HttpResponse:
    parsed = _parse_create_body(body)
    if isinstance(parsed, V1HttpResponse):
        return parsed

    try:
        rule = service.create_auto_approval_rule(
            AutoApprovalRule(
                rule_id=_new_id("apr"),
                workspace_id=identity.workspace_id,
                name=parsed.name,
                target_agent_id=parsed.target_agent_id,
                allowed_scopes=parsed.allowed_scopes,
                max_ttl_seconds=parsed.max_ttl_seconds,
                status="active",
                created_by=f"workspace:{identity.workspace_id}",
                created_at=now,
            )
        )
    except ValueError as error:
        return _error(400, "invalid_request", str(error))

    return V1HttpResponse(status_code=201, body=_rule_body(rule))


def _parse_create_body(body: object) -> ParsedCreateRuleBody | V1HttpResponse:
    if not isinstance(body, dict):
        return _error(400, "invalid_request", "request body must be a JSON object")

    required_fields = {"name", "target_agent_id", "allowed_scopes", "max_ttl_seconds"}
    body_fields = set(body)
    missing = sorted(required_fields - body_fields)
    extra = sorted(body_fields - required_fields)
    if missing:
        return _error(400, "invalid_request", f"missing required field: {missing[0]}")
    if extra:
        return _error(400, "invalid_request", f"unexpected field: {extra[0]}")

    name = body["name"]
    if not isinstance(name, str) or name == "":
        return _error(400, "invalid_request", "name must be a non-empty string")

    target_agent_id = body["target_agent_id"]
    if not isinstance(target_agent_id, str) or target_agent_id == "":
        return _error(
            400,
            "invalid_request",
            "target_agent_id must be a non-empty string",
        )

    allowed_scopes = body["allowed_scopes"]
    if not isinstance(allowed_scopes, list) or not allowed_scopes:
        return _error(400, "invalid_request", "allowed_scopes must be a non-empty array")
    if any(not isinstance(scope, str) or scope == "" for scope in allowed_scopes):
        return _error(
            400,
            "invalid_request",
            "allowed_scopes must contain only non-empty strings",
        )

    max_ttl_seconds = body["max_ttl_seconds"]
    if (
        not isinstance(max_ttl_seconds, int)
        or isinstance(max_ttl_seconds, bool)
        or max_ttl_seconds <= 0
    ):
        return _error(
            400,
            "invalid_request",
            "max_ttl_seconds must be a positive integer",
        )

    return ParsedCreateRuleBody(
        name=name,
        target_agent_id=target_agent_id,
        allowed_scopes=tuple(allowed_scopes),
        max_ttl_seconds=max_ttl_seconds,
    )


def _workspace_identity(
    headers: Mapping[str, str],
    *,
    workspace_identities: Mapping[str, WorkspaceIdentity] | None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None,
    now: datetime,
) -> WorkspaceIdentity | None:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    workspace_key = normalized_headers.get("x-workspace-key")
    if workspace_key is None:
        return None
    if workspace_identity_resolver is not None:
        return workspace_identity_resolver(workspace_key, now)
    return (workspace_identities or {}).get(workspace_key)


def _rule_body(rule: AutoApprovalRule) -> dict[str, object]:
    return {
        "rule_id": rule.rule_id,
        "workspace_id": rule.workspace_id,
        "name": rule.name,
        "target_agent_id": rule.target_agent_id,
        "allowed_scopes": list(rule.allowed_scopes),
        "max_ttl_seconds": rule.max_ttl_seconds,
        "status": rule.status,
        "created_by": rule.created_by,
        "created_at": rule.created_at.isoformat(),
        "updated_by": rule.updated_by,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at is not None else None,
    }


def _error(status_code: int, error: str, reason: str) -> V1HttpResponse:
    return V1HttpResponse(status_code=status_code, body={"error": error, "reason": reason})


def _new_id(prefix: str) -> str:
    return f"{prefix}_{token_urlsafe(16)}"
