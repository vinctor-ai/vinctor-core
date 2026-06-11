from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

STATUS_FIELDS = ("status", "service", "mode")
BOUNDARY_FIELDS = ("boundary_id", "name", "runtime", "boundary_type", "mode", "status")
GRANT_FIELDS = (
    "grant_id",
    "grant_ref",
    "workspace_id",
    "agent_id",
    "scopes",
    "status",
    "expires_at",
)
AUDIT_EVENT_FIELDS = (
    "event_id",
    "event_type",
    "decision",
    "reason",
    "workspace_id",
    "agent_id",
    "grant_id",
    "grant_ref",
    "action",
    "resource",
    "scope_attempted",
    "scope_matched",
    "boundary_id",
    "runtime",
    "boundary_type",
    "created_at",
)
GRANT_REQUEST_FIELDS = (
    "request_id",
    "workspace_id",
    "requester_agent_id",
    "target_agent_id",
    "requested_scopes",
    "requested_ttl_seconds",
    "status",
    "created_at",
    "decided_at",
    "decision_reason",
    "issued_grant_ref",
    "boundary_id",
    "requester_runtime",
    "routing_hint",
    "routing_reason",
    "queue_reason",
)
AUTO_APPROVAL_RULE_FIELDS = (
    "rule_id",
    "workspace_id",
    "name",
    "target_agent_id",
    "allowed_scopes",
    "max_ttl_seconds",
    "status",
    "created_at",
    "updated_at",
)
LIST_OF_STRING_FIELDS = frozenset({"allowed_scopes", "requested_scopes", "scopes"})
INTEGER_FIELDS = frozenset({"max_ttl_seconds", "requested_ttl_seconds"})


def allowlist_object(data: Mapping[str, Any], fields: Iterable[str]) -> dict[str, Any]:
    allowed: dict[str, Any] = {}
    for field in fields:
        if field not in data:
            continue
        filtered = _allowlisted_value(field, data[field])
        if filtered is not _DROP:
            allowed[field] = filtered
    return allowed


_DROP = object()


def _allowlisted_value(field: str, value: Any) -> Any:
    if field in LIST_OF_STRING_FIELDS:
        if not isinstance(value, list):
            return _DROP
        return [item for item in value if isinstance(item, str)]
    if field in INTEGER_FIELDS:
        if isinstance(value, bool) or not isinstance(value, int):
            return _DROP
        return value
    if value is None or isinstance(value, str):
        return value
    return _DROP
