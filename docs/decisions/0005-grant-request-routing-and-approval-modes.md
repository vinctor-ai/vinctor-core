# Grant request routing and approval modes

- status: accepted
- date: 2026-06-11

## Context

Vinctor now supports grant requests, workspace/admin approval and rejection,
admin-defined auto-approval rules, and an explicit auto-approve service path.

That does not mean every grant request should be auto-approved. Some requests
are low-risk and repeatable enough for preconfigured automatic approval. Others
need human or operator review. Some should stay pending or be rejected because
they do not fit the configured authority model.

The execution agent must not decide which approval mode applies to its own
request. Otherwise, auto-approval becomes another route to self-issued
authority.

## Decision

Grant requests should be routed into approval modes by workspace/admin
authority or a future orchestrator acting with that authority.

The requesting execution agent may:

- create a grant request
- consume an issued `grant_ref`

The requesting execution agent must not:

- choose that its own request is auto-approved
- create or edit the rules that approve its request
- invoke rule evaluation through an agent-key route
- bypass the service-issued grant lifecycle

## Approval Modes

### Auto-Approval Candidate

Use auto-approval for low-risk, repeatable, narrow requests that operators are
comfortable preauthorizing.

Good candidates:

- CI test or build execution
- narrow documentation edits
- bounded repository reads
- task-local operations with limited blast radius

An auto-approval candidate still requires:

- an active workspace/admin-defined rule
- requested scopes within the rule's allowed scopes
- requested TTL within the rule's max TTL
- requested scopes within the target agent's issuable scope bounds
- workspace/admin or future orchestrator authority to invoke auto-approval

No matching rule means the request stays pending. It is not automatically
approved and is not automatically rejected.

### Human or Operator Review

Use human or operator review for requests with higher impact, unclear intent,
or broader authority.

Good human-review candidates:

- production deploys
- refunds or billing changes
- migrations
- customer-impacting operations
- destructive repository, infrastructure, or database operations
- production secret access
- unusually broad scopes or long TTLs

This repository does not implement a human approval UI or complete approval
workflow yet. The current supported manual path is workspace/admin approval or
rejection through the service contract.

### Pending or Reject

Leave a request pending when it does not match auto-approval rules and still
needs review.

Reject a request when workspace/admin review determines that authority should
not be granted.

Common reject reasons include:

- scope outside target agent issuable bounds
- unclear or missing operator intent
- TTL longer than the task justifies
- resource taxonomy mismatch
- requested authority exceeds the task or workspace policy

## Invocation Model

The current implementation keeps request creation and auto-approval invocation
separate:

```text
agent creates grant request
workspace/admin or future orchestrator invokes auto-approve
matching rule issues a service-issued grant
non-matching request remains pending
```

A future orchestrator may call auto-approval immediately after request creation,
but only when it acts with workspace/admin or orchestrator authority. Do not add
an agent-key request option such as `auto_approve: true` that lets the
requesting agent select this path for itself.

## Consequences

- Auto-approval is opt-in through operator-defined rules, not the default path
  for every grant request.
- Human/operator review remains a first-class future direction for higher-risk
  authority.
- Non-matching auto-approval attempts preserve reviewability by leaving the
  request pending.
- Grant issuance remains mediated by the existing service-issued grant
  lifecycle.
- This does not add hosted service behavior, a human approval UI, full JIT
  orchestration, least-privilege orchestration, credential shielding, or
  provider integrations.
