# Vinctor CLI Design

This note records the local-demo CLI direction for Vinctor. The goal is to
replace repeated `python -m ...` calls with a single `vinctor` command that is
comfortable for both operators and agents while keeping authority boundaries
visible.

## Research References

- HashiCorp Vault CLI documents a single command tree, global environment
  variables, selectable output formats, and explicit exit-code behavior:
  https://developer.hashicorp.com/vault/docs/commands
- GitHub CLI uses resource-oriented commands such as `gh issue` and `gh pr`,
  with machine-readable `--json` output for automation:
  https://cli.github.com/manual/
- Kubernetes `kubectl` uses a consistent `command resource name` style and
  `-o json` / `-o yaml` output modes:
  https://kubernetes.io/docs/reference/kubectl/
- OpenFGA CLI documents config precedence across flags, environment variables,
  and `.fga.yaml`, and keeps authorization-domain resources visible:
  https://openfga.dev/docs/getting-started/cli
- 1Password CLI and Doppler CLI reinforce the same pattern: a human-friendly
  command surface with JSON output and environment/config support for
  automation:
  https://www.1password.dev/cli/reference and https://docs.doppler.com/docs/cli

## Roles

Vinctor should keep role boundaries explicit in the command tree:

```bash
vinctor service ...
vinctor local ...
vinctor agent ...
vinctor operator ...
vinctor demo ...
```

Service commands run the local/self-hostable HTTP runtime without minting new
authority. Agent commands request or consume authority. Operator commands
decide, configure, or inspect authority. Local commands prepare the prototype
service and may bootstrap local keys/grants. Demo commands are smoke checks and
walkthrough helpers, not product claims.

## Human / Operator Tasks

People are likely to directly perform:

- local service start and demo setup
- pending request queue review
- manual approve or reject
- auto-approval rule creation, listing, and disabling
- agent issuable scope bounds configuration
- audit inspection and filtering
- high-risk request review
- rule/bounds import/export review
- local storage metadata checks

These actions require workspace/admin authority and should use
`vinctor operator ...`.

## Agent Tasks

Agents should be able to perform only:

- create a grant request
- consume an issued grant through enforce
- inspect only their own request status
- parse JSON output and exit codes

Agents must not get commands for rule creation, approval, rejection, or selecting
their own approval path.

## Future Orchestrator Tasks

A future orchestrator may:

- evaluate pending requests against configured operator policy
- route manual-review requests to a human/operator inbox
- revoke grants after task/session completion
- inject runtime environment variables for hooks
- clean up expired grants

This repo should not yet claim hosted orchestration or human approval workflow.

## Command Shape

Initial commands:

```bash
vinctor service serve --host 127.0.0.1 --port 8765 --db .vinctor/vinctor.sqlite \
  --mode self_hosted

vinctor local start --db .vinctor-local.sqlite --boundary-name claude-code-local
vinctor local env
vinctor local env --write-file .vinctor.env

vinctor agent requests create --scope execute:ci/test --ttl 30m --reason "run tests" \
  --task-id task-ci --session-id session-demo --runtime codex --repo vinctor-core
vinctor agent requests status grq_...
vinctor agent enforce --action execute --resource ci/test

vinctor operator requests list --status pending
vinctor operator requests inbox
vinctor operator requests timeline grq_...
vinctor operator requests view grq_...
vinctor operator requests approve grq_... --reason "reviewed"
vinctor operator requests reject grq_... --reason "too broad"
vinctor operator requests evaluate grq_...

vinctor operator rules create --name ci-test --target-agent-id agent_local \
  --scope execute:ci/test --max-ttl 30m
vinctor operator rules list
vinctor operator rules disable apr_...

vinctor operator bounds set agent_local --scope execute:ci/test
vinctor operator bounds show agent_local
vinctor operator policy apply --file policy.yaml
vinctor operator policy export --file exported-policy.yaml

vinctor operator audit list --limit 20
vinctor operator audit list --event grant_request_auto_approved
vinctor operator audit list --request-id grq_...
vinctor operator audit list --boundary-id bnd_...
vinctor operator storage info

vinctor demo check
vinctor demo service
```

`vinctor service serve` opens existing SQLite service state and starts the HTTP
runtime. It prints listening URL, mode, database path, and a prototype warning,
but it does not print raw keys. Bootstrap remains explicit through local setup
or operator/admin flows.

`vinctor local env` is only a formatter for already-known endpoint/key values.
It must not imply that raw keys can be recovered from SQLite.

`operator requests evaluate` maps to the current auto-approval service path. The
name is intentionally broader than `auto-approve`: policy evaluation may approve
the request, or it may leave it pending for manual review.

## Output

Human output should be short and stable. JSON output is enabled with `--json` or
`-o json`.

Rules for JSON output:

- stdout contains JSON only
- errors go to stderr
- stable ids are always present
- timestamps are ISO 8601
- reason codes are stable strings

## Environment And Config

Initial environment variables:

```bash
VINCTOR_ENDPOINT
VINCTOR_WORKSPACE_KEY
VINCTOR_AGENT_KEY
VINCTOR_GRANT_REF
VINCTOR_BOUNDARY_ID
VINCTOR_DB
VINCTOR_HOST
VINCTOR_PORT
VINCTOR_SERVICE_MODE
VINCTOR_LOG_LEVEL
```

Raw keys should not be written to repo-local config. Future config/keychain work
should be ADR-backed.

## Exit Codes

```text
0 success
1 unexpected/internal error
2 CLI usage or local validation error
3 enforce denied
4 auth missing or invalid
5 service/API unavailable or remote error
```

Pending requests are not errors. A request can remain pending because no
auto-approval rule matched, because the request needs manual review, or because
an operator has not evaluated it yet.

## Migration

The current Python module commands remain developer fallbacks:

| Current | Preferred |
| --- | --- |
| `python -m vinctor_service.local_launcher` | `vinctor local start` |
| `local_admin grant-requests create` | `vinctor agent requests create` |
| n/a | `vinctor agent requests status` |
| `local_admin grant-requests list` | `vinctor operator requests list` |
| `local_admin grant-requests approve` | `vinctor operator requests approve` |
| `local_admin grant-requests reject` | `vinctor operator requests reject` |
| `local_admin grant-requests auto-approve` | `vinctor operator requests evaluate` |
| `local_admin auto-approval-rules create` | `vinctor operator rules create` |
| `local_admin auto-approval-rules list` | `vinctor operator rules list` |
| `local_admin auto-approval-rules disable` | `vinctor operator rules disable` |
| `local_admin bounds set/show` | `vinctor operator bounds set/show` |
| n/a | `vinctor operator policy apply/export` |
| `local_admin audit` | `vinctor operator audit list` |
| `local_admin enforce` | `vinctor agent enforce` |
