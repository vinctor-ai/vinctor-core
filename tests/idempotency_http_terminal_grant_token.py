from idempotency_http_terminal_models import (
    _GRANT_KEYS,
    ExpectedTerminalResponse,
    _error,
)

GRANT_TOKEN_RESPONSES = {
    "grant-success": ExpectedTerminalResponse(
        201,
        exact_values=(
            (("agent_id",), "agent_release"),
            (("expires_at",), "2026-07-19T12:01:00+00:00"),
            (("scopes",), ["write:repo/feature/readme"]),
            (("status",), "active"),
            (("workspace_id",), "ws_main"),
        ),
        prefixed_values=(
            (("audit_event_id",), "evt_"),
            (("grant_id",), "grnt_"),
            (("grant_ref",), "grt_"),
        ),
        object_keys=(((), _GRANT_KEYS),),
    ),
    "grant-service-400": _error(
        400,
        "invalid_requested_scope",
        "invalid_requested_scope",
    ),
    "grant-bounds-missing-403": _error(
        403,
        "issuable_bounds_not_found",
        "issuable_bounds_not_found",
        detail="no issuable scope bounds are configured for agent 'agent_unbounded'",
    ),
    "grant-scope-bounds-403": _error(
        403,
        "scope_outside_issuable_bounds",
        "scope_outside_issuable_bounds",
        detail=(
            "requested scope(s) read:secret/env are outside agent 'agent_release' "
            "issuable bounds (write:repo/feature/*)"
        ),
    ),
    "grant-ttl-bounds-403": _error(
        403,
        "ttl_exceeds_issuable_max",
        "ttl_exceeds_issuable_max",
        detail=("requested TTL 3601s exceeds the max issuable TTL 3600s for agent 'agent_release'"),
    ),
    "token-success": ExpectedTerminalResponse(
        201,
        exact_values=((("expires_at",), "2026-07-19T12:01:00+00:00"),),
        prefixed_values=((("token",), "vat_"), (("token_id",), "vtk_")),
        object_keys=(((), frozenset({"expires_at", "token", "token_id"})),),
    ),
    "token-forbidden": _error(
        403,
        "forbidden",
        "subject token could not be issued",
    ),
}
