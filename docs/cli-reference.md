# Vinctor CLI reference

`vinctor` is the command-line interface to the local Vinctor prototype. It runs
the authorization service, bootstraps and inspects workspace state, lets an agent
request and consume grants, and lets an operator manage rules, bounds, audit, and
keys.

This reference is organized **by the value you are working with** — the endpoint,
the keys, a grant, a boundary, and so on — because that is usually what you have
in hand ("I have a `grt_…`, what do I do with it?"). A flat
[command index](#command-index) is at the bottom. Everything here is derived from
`--help`; run `vinctor <role> <command> --help` for the authoritative, version-
specific flags.

## Invocation

```
vinctor [GLOBAL OPTIONS] <role> <command> [COMMAND OPTIONS]
```

The five roles are `service`, `local`, `agent`, `operator`, and `demo`.

> [!IMPORTANT]
> **Global options come before the role.** `vinctor --endpoint http://… operator
> audit list` works; `vinctor operator audit list --endpoint http://…` does not —
> `--endpoint` is a global option, not an `audit list` option. In practice you set
> the environment variables below once and omit the global flags.

### Global options and their environment defaults

Each global option falls back to an environment variable, so a configured shell
rarely needs to pass them explicitly. (`vinctor local env` prints these exports;
see [The runtime environment bundle](#service-endpoint-and-database).)

| Global option | Environment default | Who uses it |
| --- | --- | --- |
| `--endpoint` | `VINCTOR_ENDPOINT` | every command that talks to the service |
| `--workspace-key` | `VINCTOR_WORKSPACE_KEY` | `operator` commands (the admin key) |
| `--agent-key` | `VINCTOR_AGENT_KEY` | `agent` commands |
| `--grant-ref` | `VINCTOR_GRANT_REF` | `agent enforce` |
| `--boundary-id` | `VINCTOR_BOUNDARY_ID` | request / audit filtering |
| `--db` | `VINCTOR_DB` | service startup and `operator storage` (direct DB) |
| `--workspace-id` | _(no environment default)_ | scoping / disambiguation |
| `--agent-id` | _(no environment default)_ | scoping / disambiguation |
| `--json` / `-o {text,json}` | — | machine-readable output |

`vinctor service serve` additionally reads `VINCTOR_HOST`, `VINCTOR_PORT`,
`VINCTOR_LOG_LEVEL`, and `VINCTOR_SERVICE_MODE` as defaults for its flags. The MCP
inspection server uses a separate `VINCTOR_MCP_*` set — see
[MCP server docs](mcp-server.md).

### Authentication surfaces

Commands authenticate in one of three ways. Knowing which a command uses tells you
which key it needs:

- **`operator …`** → the **workspace key** (`wsk_…`, the admin key) over the
  endpoint. Keep it in an operator-only shell.
- **`agent …`** → the **agent key** (`aak_…`) over the endpoint.
- **`operator storage …`** → the **SQLite database directly** (`--db`), not the
  endpoint — these are offline DB-lifecycle operations.

---

## Service endpoint and database

The endpoint is the URL clients call; the database is the SQLite file the service
persists grants and audit to.

**Run the service:**

```bash
vinctor service serve --host 127.0.0.1 --port 8765 --db .vinctor/service.sqlite \
  --mode local --log-level info
```

`--mode {local,self_hosted}` selects the runtime mode (bound at startup);
`--log-level {debug,info,warning,error}` sets verbosity.

**Bootstrap everything at once (local prototype):** `vinctor local start` starts a
SQLite-backed service *and* creates a workspace, agent, grant, and boundary in one
command (see the per-value sections below for the pieces it produces):

```bash
vinctor local start --db .vinctor-local.sqlite --boundary-name claude-code-local
```

It prints copy-pasteable `VINCTOR_*` exports for the boundary caller. The default
port is `8765`; pass a free `--port` if it is taken.

**Print the runtime environment bundle:** `vinctor local env` writes the
`VINCTOR_*` exports from the current or stored values:

```bash
vinctor local env                      # print exports
vinctor local env --write-file env.sh  # write them (use --force to overwrite)
```

---

## Workspace (workspace id and workspace key `wsk_…`)

The workspace is the tenant boundary; the **workspace key** is the admin key that
authorizes every `operator` command.

- **Created by** `vinctor local start` — it bootstraps the workspace and prints the
  `wsk_…` key once. Pass `--workspace-id` / `--workspace-key` to pin them, or let
  it generate them.
- **Rotated by** `vinctor operator keys rotate workspace` — issues fresh key
  material; the new raw key is printed once and is not recoverable afterward.
- **Listed by** `vinctor operator keys list`; **revoked by**
  `vinctor operator keys revoke <key_id>`.
- **Consumed via** `--workspace-key` / `VINCTOR_WORKSPACE_KEY` by all `operator`
  commands.

---

## Agent (agent id and agent key `aak_…`)

An agent identity is what a runtime presents when it calls `/v1/enforce`; the
**agent key** authenticates it.

- **Created by** `vinctor local start` (`--agent-id` / `--agent-key`, printed once).
- **Rotated by** `vinctor operator keys rotate agent`.
- **Listed / revoked** through `vinctor operator keys list` /
  `vinctor operator keys revoke <key_id>`.
- **Consumed via** `--agent-key` / `VINCTOR_AGENT_KEY` by all `agent` commands.

For creating multiple agents and the manual end-to-end setup, see the
[Configure agents and grants guide](https://github.com/pkachuc/vinctor-site/blob/main/docs/getting-started/agents-and-grants.md).

---

## Grant (grant ref `grt_…`, grant id, scopes, TTL)

A grant is the scoped, time-boxed permission set each tool call is checked against.

**Bootstrap path** — `vinctor local start` issues one with the workspace:

```bash
vinctor local start --db .vinctor-local.sqlite \
  --scope "write:repo/feature/*" --grant-ttl-hours 8 \
  --grant-id grant_local --grant-ref grt_local
```

`--scope` is repeatable; `--grant-ttl-hours` sets the lifetime; `--grant-id` /
`--grant-ref` pin identifiers (otherwise generated).

**Request → approval path** — the agent asks, the operator decides:

```bash
# agent: ask for a grant
vinctor agent requests create --scope "write:repo/feature/*" --ttl 8h \
  --reason "feature work" --runtime claude-code --boundary-id bnd_…
# operator: see and act on it
vinctor operator requests list --status pending
vinctor operator requests view <request_id>
vinctor operator requests approve <request_id> --reason "ok"   # or: reject
vinctor operator requests evaluate <request_id>                # auto-decide via rules
# agent: check the outcome
vinctor agent requests status <request_id>
```

`agent requests create` also accepts `--task-id`, `--session-id`, `--repo`, and
`--worktree` to tag the request. `operator requests` additionally offers `inbox`
and `timeline` views.

> [!NOTE]
> Duration flags — `--ttl` (here) and `--max-ttl` (bounds and rules) — accept
> `<n>s`, `<n>m`, or `<n>h`, or a plain number of seconds. (`local start
> --grant-ttl-hours` is a separate integer-hours flag.)

**Consumed via** `--grant-ref` / `VINCTOR_GRANT_REF` when a call is enforced.

---

## Issuable bounds

Bounds cap what any grant issued for an agent may contain — a ceiling enforced at
issue time.

```bash
vinctor operator bounds set --scope "write:repo/feature/*" --max-ttl 24h
vinctor operator bounds show
```

`--scope` is repeatable; `--max-ttl` caps grant lifetime.

---

## Approval rules and policy

Rules let the operator auto-approve matching requests; a policy file bundles bounds
and rules together.

```bash
vinctor operator rules create --name ci-auto --target-agent-id agent_ci \
  --scope "execute:ci/test" --max-ttl 1h
vinctor operator rules list
vinctor operator rules disable <rule_id>

vinctor operator policy apply  --file policy.yaml   # bounds + rules in one file
vinctor operator policy export --file policy.yaml
```

For the policy-file format, see
[Operator policy authoring](operator-policy-authoring/policy-file.md).

---

## Boundary (boundary id `bnd_…`, name / runtime / type)

A boundary records which runtime/adapter a decision came from, for audit.

- **Created by** `vinctor local start` via `--boundary-name`,
  `--boundary-runtime`, and `--boundary-type` (the `bnd_…` id is printed).
- **Referenced via** `--boundary-id` / `VINCTOR_BOUNDARY_ID`, and on
  `agent requests create --boundary-id …`.
- **Filters** `operator audit list --boundary-id …`.

---

## Audit

Every permit and deny is recorded; the operator reads or exports it.

```bash
vinctor operator audit list --limit 50 \
  --event action_denied --grant-ref grt_… --boundary-id bnd_… --request-id …
vinctor operator audit export --format jsonl --file audit.jsonl
```

All `audit list` filters are optional. `audit export` currently supports
`--format jsonl`.

---

## Storage (database lifecycle)

These operate on the SQLite `--db` **directly** (not the endpoint).

```bash
vinctor operator storage backup --output backup.sqlite   # --force to overwrite
vinctor operator storage restore --input backup.sqlite --yes
vinctor operator storage reset --yes
vinctor operator storage migrate
```

`reset` and `restore` are destructive and require `--yes`.

---

## Enforce (the decision call)

Test a permit/deny directly against a grant, without a runtime adapter:

```bash
vinctor agent enforce --grant-ref grt_… --action write --resource repo/feature/README.md
```

`--grant-ref` falls back to `VINCTOR_GRANT_REF`. This is the same `/v1/enforce`
decision a runtime adapter triggers.

---

## Service info and demo

```bash
vinctor operator service info        # service mode and metadata
vinctor demo check                   # local self-check
vinctor demo service --scenario …    # scripted demonstration service
```

---

## How values are created

The CLI has **no** standalone `create workspace` / `create agent` /
`issue grant` command. Values come into existence two ways:

1. **Bootstrap** — `vinctor local start` creates a workspace, an agent, a grant,
   and a boundary together and prints the keys and exports. This is the fastest
   local path.
2. **Request → approval** — an agent calls `agent requests create`; an operator
   `approve`s it (or `evaluate`s it against auto-approval rules) to issue a grant.

Either way, **raw keys (`wsk_…`, `aak_…`, `grt_…`) are printed once and are not
recoverable** — capture them when shown. Rotate with `operator keys rotate`.

---

## Command index

| Role | Commands |
| --- | --- |
| `service` | `serve` |
| `local` | `start`, `env` |
| `agent` | `requests create`, `requests status`, `enforce` |
| `operator requests` | `list`, `inbox`, `timeline`, `view`, `approve`, `reject`, `evaluate` |
| `operator rules` | `create`, `list`, `disable` |
| `operator bounds` | `set`, `show` |
| `operator audit` | `list`, `export` |
| `operator policy` | `apply`, `export` |
| `operator storage` | `backup`, `reset`, `restore`, `migrate` |
| `operator keys` | `list`, `revoke`, `rotate {workspace,agent}` |
| `operator service` | `info` |
| `demo` | `check`, `service` |

Run any command with `--help` for its exact, version-specific options.
