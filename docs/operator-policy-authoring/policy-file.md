# Policy File Import/Export

Vinctor local demos can load operator-authored policy inputs from a
`policy.yaml` file. The file configures two service-layer concepts:

- agent issuable scope bounds
- auto-approval rules

This file does not grant authority by itself. It configures the service path
that decides whether a later grant request can be issued or auto-approved.

## Example

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
    status: active
```

Apply it to the local SQLite service database:

```bash
vinctor --db .vinctor-local.sqlite \
  --workspace-id ws_local \
  operator policy apply --file policy.yaml
```

Export the current local service policy:

```bash
vinctor --db .vinctor-local.sqlite \
  --workspace-id ws_local \
  operator policy export --file exported-policy.yaml
```

## Schema

Top-level fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `version` | Yes | Must be `1`. |
| `workspace_id` | No | If present, must match the selected workspace. |
| `agent_bounds` | No | List of agent issuance bounds. |
| `auto_approval_rules` | No | List of operator-defined auto-approval rules. |

`agent_bounds` entries:

| Field | Required | Meaning |
| --- | --- | --- |
| `agent_id` | Yes | Agent whose future issued grants are constrained. |
| `scopes` | Yes | Non-empty list of valid grant scopes. |

`auto_approval_rules` entries:

| Field | Required | Meaning |
| --- | --- | --- |
| `rule_id` | No | Stable id. If omitted, Vinctor derives one from rule content. |
| `name` | Yes | Operator-readable rule name. |
| `target_agent_id` | Yes | Agent the rule can approve requests for. |
| `allowed_scopes` | Yes | Non-empty list of grant scopes the request must fit within. |
| `max_ttl` or `max_ttl_seconds` | Yes | Maximum requested grant TTL. |
| `status` | No | `active` by default; may be `disabled`. |

`max_ttl` accepts `s`, `m`, and `h` suffixes, such as `900s`, `30m`, or `2h`.

## Import Behavior

Policy apply is idempotent for explicit `rule_id` values:

- missing bounds are created
- existing bounds for an agent are replaced
- missing rules are created
- existing rules with the same `rule_id` in the workspace are updated

Rules cannot cross workspace boundaries. A `rule_id` that already belongs to a
different workspace is rejected.

## Current Boundary

Policy import/export currently targets the local SQLite-backed prototype. It is
intended for local demos and repeatable operator setup, not hosted policy
distribution.

Additional demo templates live in `docs/examples/policies/`.
