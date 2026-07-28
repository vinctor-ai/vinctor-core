from __future__ import annotations

EXPECTED_LEGACY_RESPONSES: tuple[tuple[int, str, int, bytes], ...] = (
    (
        201,
        "application/json",
        264,
        b'{"agent_id": "agent_release", "audit_event_id": "evt_pin_direct_grant", '
        b'"expires_at": "2026-07-19T12:01:00+00:00", "grant_id": "grnt_pin_direct", '
        b'"grant_ref": "grt_pin_direct", "scopes": ["write:repo/feature/readme"], '
        b'"status": "active", "workspace_id": "ws_main"}',
    ),
    (
        201,
        "application/json",
        100,
        b'{"expires_at": "2026-07-19T12:01:00+00:00", "token": "vat_pin_legacy", '
        b'"token_id": "vtk_pin_legacy"}',
    ),
    (
        201,
        "application/json",
        151,
        b'{"boundary_id": "bnd_pin_legacy", "boundary_type": "pretooluse", '
        b'"mode": "fail_closed", "name": "pin-boundary", "runtime": "codex", '
        b'"status": "active"}',
    ),
    (
        201,
        "application/json",
        319,
        b'{"allowed_scopes": ["write:repo/feature/*"], '
        b'"created_at": "2026-07-19T12:00:00+00:00", '
        b'"created_by": "workspace:ws_main", "max_ttl_seconds": 3600, '
        b'"name": "pin-rule", "rule_id": "apr_pin_legacy", "status": "active", '
        b'"target_agent_id": "agent_release", "updated_at": null, "updated_by": null, '
        b'"workspace_id": "ws_main"}',
    ),
    (
        200,
        "application/json",
        861,
        b'{"audit_event_id": "evt_pin_approve_decision", "boundary_id": null, '
        b'"created_at": "2026-07-19T12:00:00+00:00", '
        b'"decided_at": "2026-07-19T12:00:00+00:00", '
        b'"decided_by": "workspace:ws_main", "decision_reason": null, '
        b'"grant": {"agent_id": "agent_release", '
        b'"expires_at": "2026-07-19T13:00:00+00:00", '
        b'"grant_id": "grnt_pin_approve", "grant_ref": "grt_pin_approve", '
        b'"scopes": ["write:repo/feature/readme"], "status": "active", '
        b'"workspace_id": "ws_main"}, "issued_grant_ref": "grt_pin_approve", '
        b'"reason": "pin legacy decision semantics", "repo": null, '
        b'"request_id": "grq_approve", '
        b'"requested_scopes": ["write:repo/feature/readme"], '
        b'"requested_ttl_seconds": 3600, "requester_agent_id": "agent_release", '
        b'"requester_runtime": null, "session_id": null, "status": "approved", '
        b'"target_agent_id": "agent_release", "task_id": null, '
        b'"workspace_id": "ws_main", "worktree": null}',
    ),
    (
        200,
        "application/json",
        611,
        b'{"audit_event_id": "evt_pin_reject_decision", "boundary_id": null, '
        b'"created_at": "2026-07-19T12:00:00+00:00", '
        b'"decided_at": "2026-07-19T12:00:00+00:00", '
        b'"decided_by": "workspace:ws_main", "decision_reason": null, '
        b'"issued_grant_ref": null, "reason": "pin legacy decision semantics", '
        b'"repo": null, "request_id": "grq_reject", '
        b'"requested_scopes": ["write:repo/feature/readme"], '
        b'"requested_ttl_seconds": 3600, "requester_agent_id": "agent_release", '
        b'"requester_runtime": null, "session_id": null, "status": "rejected", '
        b'"target_agent_id": "agent_release", "task_id": null, '
        b'"workspace_id": "ws_main", "worktree": null}',
    ),
    (
        200,
        "application/json",
        990,
        b'{"audit_event_id": "evt_pin_auto_decision", '
        b'"auto_approval": {"decision": "approved", '
        b'"reason": "grant_request_auto_approved", "rule_id": "apr_pin_legacy"}, '
        b'"boundary_id": null, "created_at": "2026-07-19T12:00:00+00:00", '
        b'"decided_at": "2026-07-19T12:00:00+00:00", '
        b'"decided_by": "workspace:ws_main", '
        b'"decision_reason": "auto_approval_rule:apr_pin_legacy", '
        b'"grant": {"agent_id": "agent_release", '
        b'"expires_at": "2026-07-19T13:00:00+00:00", '
        b'"grant_id": "grnt_pin_auto", "grant_ref": "grt_pin_auto", '
        b'"scopes": ["write:repo/feature/readme"], "status": "active", '
        b'"workspace_id": "ws_main"}, "issued_grant_ref": "grt_pin_auto", '
        b'"reason": "pin legacy decision semantics", "repo": null, '
        b'"request_id": "grq_auto", '
        b'"requested_scopes": ["write:repo/feature/readme"], '
        b'"requested_ttl_seconds": 3600, "requester_agent_id": "agent_release", '
        b'"requester_runtime": null, "session_id": null, "status": "approved", '
        b'"target_agent_id": "agent_release", "task_id": null, '
        b'"workspace_id": "ws_main", "worktree": null}',
    ),
)
