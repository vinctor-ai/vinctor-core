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


def allowlist_object(data: Mapping[str, Any], fields: Iterable[str]) -> dict[str, Any]:
    return {field: data[field] for field in fields if field in data}
