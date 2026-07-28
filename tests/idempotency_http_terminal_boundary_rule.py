from idempotency_http_terminal_models import ExpectedTerminalResponse, _error

BOUNDARY_RULE_RESPONSES = {
    "boundary-success": ExpectedTerminalResponse(
        201,
        exact_values=(
            (("boundary_type",), "pretooluse"),
            (("mode",), "fail_closed"),
            (("name",), "matrix-boundary"),
            (("runtime",), "codex"),
            (("status",), "active"),
        ),
        prefixed_values=((("boundary_id",), "bnd_"),),
        object_keys=(
            (
                (),
                frozenset(
                    {
                        "boundary_id",
                        "boundary_type",
                        "mode",
                        "name",
                        "runtime",
                        "status",
                    }
                ),
            ),
        ),
    ),
    "boundary-semantic-400": _error(
        400,
        "invalid_request",
        "boundary name must be unique within workspace",
    ),
    "rule-success": ExpectedTerminalResponse(
        201,
        exact_values=(
            (("allowed_scopes",), ["write:repo/feature/*"]),
            (("created_at",), "2026-07-19T12:00:00+00:00"),
            (("created_by",), "workspace:ws_main"),
            (("max_ttl_seconds",), 3_600),
            (("name",), "matrix-rule-route"),
            (("status",), "active"),
            (("target_agent_id",), "agent_release"),
            (("updated_at",), None),
            (("updated_by",), None),
            (("workspace_id",), "ws_main"),
        ),
        prefixed_values=((("rule_id",), "apr_"),),
        object_keys=(
            (
                (),
                frozenset(
                    {
                        "allowed_scopes",
                        "created_at",
                        "created_by",
                        "max_ttl_seconds",
                        "name",
                        "rule_id",
                        "status",
                        "target_agent_id",
                        "updated_at",
                        "updated_by",
                        "workspace_id",
                    }
                ),
            ),
        ),
    ),
    "rule-semantic-400": _error(
        400,
        "invalid_request",
        "invalid allowed scope: bad scope",
    ),
}
