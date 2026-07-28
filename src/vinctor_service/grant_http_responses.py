from __future__ import annotations

from vinctor_core.models import Grant
from vinctor_service.v1_http import V1HttpResponse


def grant_body(grant: Grant) -> dict[str, object]:
    return {
        "grant_id": grant.grant_id,
        "grant_ref": grant.grant_ref,
        "workspace_id": grant.workspace_id,
        "agent_id": grant.agent_id,
        "scopes": list(grant.scopes),
        "status": grant.status,
        "expires_at": grant.expires_at.isoformat() if grant.expires_at is not None else None,
    }


def error_response(
    status_code: int,
    error: str,
    reason: str,
    detail: str | None = None,
) -> V1HttpResponse:
    body: dict[str, object] = {"error": error, "reason": reason}
    if detail is not None:
        body["detail"] = detail
    return V1HttpResponse(status_code=status_code, body=body)


BAD_GRANT_REQUEST_REASONS = {
    "invalid_workspace_id",
    "invalid_agent_id",
    "invalid_ttl",
    "ttl_exceeds_max",
    "missing_requested_scopes",
    "invalid_requested_scope",
    "invalid_issuable_scope_bound",
    "duplicate_grant_ref",
}
