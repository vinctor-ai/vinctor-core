# Approval Mode Examples

These examples help operators decide whether a grant request should be handled
by auto-approval, human/operator review, or rejection.

Auto-approval is not the default for every request. It is an opt-in path for
low-risk, repeatable work that has an active workspace/admin-defined rule.

## CI Test

Recommended mode: auto-approval candidate.

Request:

```text
execute:ci/test
TTL: 30 minutes
Reason: run CI validation for the current task
```

Good auto-approval rule:

```text
target agent: agent_runner
allowed scopes: execute:ci/test
max TTL: 3600 seconds
```

Why: narrow, repeatable, low-risk, and useful for fast task feedback.

## Documentation Edit

Recommended mode: auto-approval candidate when scope is narrow.

Request:

```text
write:repo/docs/*
TTL: 1 hour
Reason: update operator documentation
```

Good auto-approval rule:

```text
target agent: agent_docs
allowed scopes: write:repo/docs/*
max TTL: 7200 seconds
```

Why: bounded repository area and limited blast radius.

Avoid auto-approving broad variants such as:

```text
write:repo/*
```

## Staging Deploy

Recommended mode: usually human/operator review first; auto-approval only after
the workspace has a mature staging policy.

Request:

```text
execute:deploy/staging
TTL: 1 hour
Reason: deploy staging preview for validation
```

Human review may be appropriate when staging has shared resources, customer
data, or external side effects.

## Production Deploy

Recommended mode: human/operator review.

Request:

```text
execute:deploy/production
TTL: 1 hour
Reason: release version 1.2.3
```

Why: production deploys are customer-impacting and should not be silently
approved by a generic automation rule.

## Secret Read

Recommended mode: human/operator review, or reject if intent is unclear.

Request:

```text
read:secret/prod
TTL: 30 minutes
Reason: inspect production credentials
```

Why: production secret access is high-risk. Operators should require clear task
context and a narrow resource label.

Safer alternatives may use narrower labels:

```text
read:secret/env/dev
read:secret/package-registry/read-only
```

## Destructive Action

Recommended mode: human/operator review or reject.

Request:

```text
delete:repo/*
TTL: 1 hour
Reason: clean up files
```

Likely outcome: reject and ask for a narrower request.

Better request:

```text
delete:repo/tmp/generated/*
TTL: 15 minutes
Reason: remove generated build artifacts
```

## Disabled Rules

Disable auto-approval rules when:

- a scope is under incident review
- a rule is broader than intended
- a workspace wants to temporarily require manual review
- a target agent is being rotated or investigated

Disabled rules should cause matching requests to stay pending rather than being
auto-approved.
