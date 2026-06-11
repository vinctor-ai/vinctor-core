# Local V1 API Contract

This document records the current local prototype HTTP contract. It does not
claim hosted service behavior or production readiness.

Machine-readable schema: `docs/openapi/v1.yaml`.

## Health

`GET /healthz`

Auth: none

Response:

```json
{
  "status": "ok",
  "service": "vinctor-service",
  "mode": "local"
}
```

The health response intentionally omits secrets, raw keys, grant refs, database
paths, and internal configuration.

## Authentication Headers

| Header | Used by | Meaning |
| --- | --- | --- |
| `X-Agent-Key` | Agent routes | Lets an execution agent request or consume authority. |
| `X-Workspace-Key` | Operator routes | Lets workspace/admin authority issue, decide, or configure authority. |
| `X-Vinctor-Boundary-Id` | `POST /v1/enforce` | Optional runtime boundary context for audit. |

Execution agents must not approve their own grant requests, create
auto-approval rules, issue grants directly, or change issuable scope bounds.

## Enforce

`POST /v1/enforce`

Auth: `X-Agent-Key`

Body:

```json
{
  "grant_ref": "grt_...",
  "action": "execute",
  "resource": "ci/test"
}
```

Responses:

- `200` with `decision: permit`
- `403` with `decision: deny`
- `400` for malformed body
- `401` for missing or invalid agent key

## Grant Requests

`POST /v1/grant-requests`

Auth: `X-Agent-Key`

Body:

```json
{
  "scopes": ["execute:ci/test"],
  "ttl_seconds": 1800,
  "reason": "run CI validation",
  "task_id": "task-ci",
  "session_id": "session-demo",
  "boundary_id": "bnd_...",
  "requester_runtime": "codex",
  "repo": "vinctor-core",
  "worktree": "feature/demo"
}
```

`task_id`, `session_id`, `boundary_id`, `requester_runtime`, `repo`, and
`worktree` are optional metadata fields for demo UX, approval queue context, and
audit correlation. They are not authority by themselves.

The create response includes non-authoritative routing hints:

```json
{
  "request_id": "grq_...",
  "status": "pending",
  "routing_hint": "auto_approval_available",
  "routing_reason": "auto_approval_match"
}
```

Routing hints describe the service's current state. They do not let the agent
choose an approval path.

`GET /v1/grant-requests/{request_id}`

Auth: `X-Agent-Key` or `X-Workspace-Key`

With `X-Agent-Key`, the service returns only requests belonging to that agent in
the same workspace. The response omits operator identity fields such as
`decided_by`.

With `X-Workspace-Key`, the service returns the operator view, including
`routing_hint`, `routing_reason`, and `queue_reason`.

`GET /v1/grant-requests`

Auth: `X-Workspace-Key`

Returns the workspace request queue. Each request includes requester, target,
requested scopes, requested TTL, status, original reason, and current queue
reason.

`POST /v1/grant-requests/{request_id}/auto-approve`

Auth: `X-Workspace-Key`

Evaluates the pending request against active operator-defined auto-approval
rules. A matching rule approves the request and issues a scoped grant. A
non-match leaves the request pending.

`POST /v1/grant-requests/{request_id}/approve`

Auth: `X-Workspace-Key`

Optional body:

```json
{
  "decision_reason": "manual operator review"
}
```

Approves the request and issues a scoped grant through the same service-issued
grant path.

`POST /v1/grant-requests/{request_id}/reject`

Auth: `X-Workspace-Key`

Optional body:

```json
{
  "decision_reason": "not needed for this task"
}
```

Rejects the request without issuing a grant.

## Grants

`POST /v1/grants`

Auth: `X-Workspace-Key`

Issues a scoped grant directly through workspace/admin authority. This route is
not available to `X-Agent-Key`.

`GET /v1/grants/{grant_ref}`

Auth: `X-Workspace-Key`

Looks up a grant in the workspace.

`POST /v1/grants/{grant_ref}/revoke`

Auth: `X-Workspace-Key`

Revokes a grant.

## Auto-Approval Rules

`POST /v1/auto-approval-rules`

Auth: `X-Workspace-Key`

Creates an operator-defined auto-approval rule.

`GET /v1/auto-approval-rules`

Auth: `X-Workspace-Key`

Lists workspace rules.

`POST /v1/auto-approval-rules/{rule_id}/disable`

Auth: `X-Workspace-Key`

Disables a rule.

## Boundaries

`POST /v1/boundaries`, `GET /v1/boundaries`,
`GET /v1/boundaries/{boundary_id}`,
`POST /v1/boundaries/{boundary_id}/disable`, and
`POST /v1/boundaries/{boundary_id}/enable` are workspace-key-protected local
boundary registry routes.

## Reason Codes

Common grant request and auto-approval reasons:

| Reason | Meaning |
| --- | --- |
| `grant_requested` | Agent request was accepted into pending queue. |
| `auto_approval_match` | An active rule would approve the request. |
| `no_matching_rule` | No active rule matched the target agent. |
| `scope_outside_rule` | A rule candidate existed, but requested scopes were outside it. |
| `ttl_exceeds_rule` | A rule candidate existed, but requested TTL was too long. |
| `grant_request_auto_approved` | Workspace-triggered auto-approval issued a grant. |
| `grant_request_approved` | Workspace/admin manually approved the request. |
| `grant_request_rejected` | Workspace/admin rejected the request. |
| `scope_outside_issuable_bounds` | Approval could not issue because request exceeded agent bounds. |
| `grant_request_not_pending` | A decided request cannot be decided again. |

Reason codes are stable enough for local demos and tests, but still part of the
early prototype contract.
