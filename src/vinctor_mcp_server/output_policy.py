from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Literal

OutputMode = Literal["safe", "diagnostic"]

STATUS_FIELDS = ("status", "service", "mode")
BOUNDARY_FIELDS = ("boundary_id", "name", "runtime", "boundary_type", "mode", "status")
GRANT_SAFE_FIELDS = (
    "grant_id",
    "grant_ref",
    "workspace_id",
    "agent_id",
    "status",
    "expires_at",
)
GRANT_DIAGNOSTIC_FIELDS = ("scopes",)
AUDIT_EVENT_SAFE_FIELDS = (
    "event_id",
    "event_type",
    "event_class",
    "decision",
    "reason",
    "workspace_id",
    "agent_id",
    "grant_id",
    "grant_ref",
    "action",
    "resource",
    "boundary_id",
    "runtime",
    "boundary_type",
    "created_at",
    "subject_token_verified",
    "enforcing_principal",
    "reason_code",
    "occurrence_count",
    "first_seen_at",
    "last_seen_at",
)
AUDIT_EVENT_DIAGNOSTIC_FIELDS = ("scope_attempted", "scope_matched", "token_id")
GRANT_REQUEST_SAFE_FIELDS = (
    "request_id",
    "workspace_id",
    "requester_agent_id",
    "target_agent_id",
    "requested_ttl_seconds",
    "reason",
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
GRANT_REQUEST_DIAGNOSTIC_FIELDS = ("requested_scopes",)
AUTO_APPROVAL_RULE_SAFE_FIELDS = (
    "rule_id",
    "workspace_id",
    "name",
    "target_agent_id",
    "max_ttl_seconds",
    "status",
    "created_by",
    "created_at",
    "updated_by",
    "updated_at",
)
AUTO_APPROVAL_RULE_DIAGNOSTIC_FIELDS = ("allowed_scopes",)
AUTO_APPROVAL_EVALUATION_FIELDS = ("decision", "reason", "rule_id")
LIST_OF_STRING_FIELDS = frozenset({"allowed_scopes", "requested_scopes", "scopes"})
INTEGER_FIELDS = frozenset(
    {"max_ttl_seconds", "occurrence_count", "requested_ttl_seconds"}
)
BOOLEAN_FIELDS = frozenset({"subject_token_verified"})


def fields_for_mode(
    safe_fields: tuple[str, ...],
    diagnostic_fields: tuple[str, ...],
    mode: OutputMode,
) -> tuple[str, ...]:
    if mode == "diagnostic":
        return (*safe_fields, *diagnostic_fields)
    return safe_fields


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
    if field in BOOLEAN_FIELDS:
        if not isinstance(value, bool):
            return _DROP
        return value
    if value is None or isinstance(value, str):
        return value
    return _DROP
