# Demo Service Runbook

This runbook shows the local prototype as a small service-like flow:

1. start local service
2. apply operator policy
3. create an agent grant request
4. evaluate or manually decide the request
5. enforce an action with the issued grant
6. inspect audit

It does not require changing sibling hook repositories.

## Start The Local Service

```bash
vinctor local start \
  --db .vinctor-local.sqlite \
  --workspace-id ws_local \
  --agent-id agent_local \
  --boundary-name claude-code-local
```

Copy the printed `VINCTOR_*` exports into the shell that will run CLI or hook
calls.

## Apply Policy

Create `policy.yaml`:

```yaml
version: 1
workspace_id: ws_local
agent_bounds:
  - agent_id: agent_local
    scopes:
      - execute:ci/test
      - write:repo/vinctor-core/*
auto_approval_rules:
  - rule_id: apr_ci
    name: CI auto approval
    target_agent_id: agent_local
    allowed_scopes:
      - execute:ci/test
    max_ttl: 30m
```

Apply it:

```bash
vinctor --db .vinctor-local.sqlite \
  --workspace-id ws_local \
  operator policy apply --file policy.yaml
```

## Auto-Approved Request

```bash
vinctor agent requests create \
  --scope execute:ci/test \
  --ttl 15m \
  --reason "run CI validation"
```

The response should show `routing=auto_approval_available`.

```bash
vinctor operator requests evaluate <request_id>
```

If a rule matches, the request is approved and the response includes
`grant_ref`.

```bash
vinctor agent enforce \
  --grant-ref <grant_ref> \
  --action execute \
  --resource ci/test
```

## Manual-Review Request

```bash
vinctor agent requests create \
  --scope write:repo/vinctor-core/README.md \
  --ttl 30m \
  --reason "edit core README"
```

The response should show `routing=manual_review_required` because no
auto-approval rule covers the write scope.

```bash
vinctor operator requests evaluate <request_id>
```

The request remains pending. The operator can then approve or reject it:

```bash
vinctor operator requests approve <request_id> \
  --reason "manual operator review"
```

or:

```bash
vinctor operator requests reject <request_id> \
  --reason "not needed for this task"
```

## Agent Status

An agent can check its own request without seeing the full workspace queue:

```bash
vinctor agent requests status <request_id>
```

Agents cannot list all requests or approve requests.

## Queue And Audit

Show pending requests:

```bash
vinctor operator requests list --status pending
```

Show request audit:

```bash
vinctor --db .vinctor-local.sqlite \
  operator audit list --request-id <request_id>
```

Show storage metadata:

```bash
vinctor --db .vinctor-local.sqlite operator storage info
```

## Smoke Check

For a single local sanity check:

```bash
vinctor demo check
```

The command creates a temporary local service, creates a rule, creates a grant
request, auto-approves it, enforces an action, and verifies audit was written.
