# Approval authority and auto-approval rules

- status: accepted
- date: 2026-06-11

## Context

Vinctor now supports service-issued scoped grants and a grant request lifecycle.
Execution agents can request authority, but they must not mint that authority
for themselves.

The next product direction is automatic approval. Automatic approval must still
be mediated by an authority outside the execution agent. Otherwise, an
execution agent could turn a request into a grant by changing or selecting the
rules that approve it.

## Decision

Auto-approval rules are workspace/admin-controlled policy data.

Execution agents may:

- create grant requests
- consume issued `grant_ref` values through enforce

Execution agents must not:

- create auto-approval rules
- update auto-approval rules
- enable or disable auto-approval rules
- approve their own requests by invoking an agent-key route
- bypass the service-issued grant path

Workspace/admin authority may define auto-approval rules. A future
orchestrator may also evaluate or manage rules only when it acts with
workspace/admin authority, not as the requesting execution agent.

The first implementation step was a dry-run evaluator:

- It evaluates a pending grant request against admin-defined rules.
- It returns why the request would or would not be auto-approved.
- It does not mutate the request.
- It does not issue a grant.

The next explicit slice connects matching rules to automatic approval:

- It evaluates a pending grant request against active admin-defined rules.
- It leaves non-matching requests pending.
- It reuses the existing grant request approval and service-issued grant
  lifecycle when a rule matches.
- It still validates agent issuable scope bounds before issuing a grant.
- It writes `grant_request_auto_approved` audit events for auto-approved
  requests.

This path must still be invoked with workspace/admin authority or future
orchestrator authority, not by the requesting execution agent.

## HTTP/Admin Contract

Auto-approval rule management is exposed only through workspace/admin authority:

- `POST /v1/auto-approval-rules`
- `GET /v1/auto-approval-rules`
- `POST /v1/auto-approval-rules/{rule_id}/disable`
- `POST /v1/grant-requests/{request_id}/auto-approve`

These routes use `X-Workspace-Key`, not `X-Agent-Key`. The requesting execution
agent must not create, list, disable, or otherwise select the rules that may
approve its own grant request.

The rule management routes manage rule data only. The grant request
`auto-approve` route attempts automatic approval through the service path. It
does not add a human approval workflow.

## Rule Shape

The initial rule model should stay small:

- workspace id
- rule id and name
- target agent id
- allowed scopes
- max TTL seconds
- status: `active` or `disabled`
- created/updated metadata controlled by workspace/admin authority

The evaluator should treat requested scopes as valid only when every requested
scope is within the rule's allowed scopes. A requested TTL must be less than or
equal to the rule's max TTL.

## Consequences

- Automatic approval remains reviewable and testable through the dry-run
  evaluator and explicit service path.
- The requesting execution agent cannot expand its own authority by editing
  approval rules or invoking rule evaluation through an agent-key route.
- Non-matching requests remain pending; this slice should not introduce
  automatic rejection.
- This does not add a human approval UI, hosted service, dynamic hook behavior,
  full JIT orchestration, least-privilege orchestration, credential shielding,
  or provider integration.
