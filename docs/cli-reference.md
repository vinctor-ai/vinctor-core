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
> `--endpoint` is a global option, not an `audit list` option. This applies to
> output flags too: `vinctor -o json agent enforce …` works, but
> `vinctor agent enforce -o json …` is rejected as an unknown option. In practice
> you set the environment variables below once and omit the global flags.

### Global options and their environment defaults

Each global option falls back to an environment variable, so a configured shell
rarely needs to pass them explicitly. (`vinctor local env` prints these exports;
see [The runtime environment bundle](#service-endpoint-and-database).)

| Global option | Environment default | Who uses it |
| --- | --- | --- |
| `--endpoint` | `VINCTOR_ENDPOINT` | every command that talks to the service |
| `--workspace-key` | `VINCTOR_WORKSPACE_KEY` | the HTTP `operator` commands (`requests`, `rules`) — the admin key |
| `--agent-key` | `VINCTOR_AGENT_KEY` | `agent` commands |
| `--grant-ref` | `VINCTOR_GRANT_REF` | `agent enforce` |
| `--boundary-id` | `VINCTOR_BOUNDARY_ID` | request / audit filtering |
| `--db` | `VINCTOR_DB` | service startup and the direct-DB `operator` commands |
| `--workspace-id` | _(no environment default)_ | required by the direct-DB `operator` commands |
| `--agent-id` | _(no environment default)_ | scoping (e.g. `operator keys rotate agent`) |
| `--json` / `-o {text,json}` | — | machine-readable output |

`vinctor service serve` additionally reads `VINCTOR_HOST`, `VINCTOR_PORT`,
`VINCTOR_LOG_LEVEL`, and `VINCTOR_SERVICE_MODE` as defaults for its flags. The MCP
inspection server uses a separate `VINCTOR_MCP_*` set — see
[MCP server docs](mcp-server.md).

### How commands reach Vinctor

Commands talk to Vinctor in one of two ways, and which one a command uses
determines its required inputs:

- **Over HTTP, authenticated by a key** (needs `--endpoint` and the key; the key
  identifies the workspace, so no `--workspace-id`):
  - `agent …` → the **agent key** (`aak_…` / `VINCTOR_AGENT_KEY`).
  - `operator requests …` and `operator rules …` → the **workspace key**
    (`wsk_…` / `VINCTOR_WORKSPACE_KEY`). Keep it in an operator-only shell.
- **Directly on the SQLite database** (needs `--db` and `--workspace-id`; no key,
  no endpoint): `operator bounds`, `operator audit list`, `operator policy`,
  `operator storage`, `operator service`, `operator keys`, `operator tokens`, and
  the `operator require-subject-token` / `require-pop` / `require-boundary`
  mandates.

Two commands are **hybrid** — they read the `--db` directly but still require a
key to scope the result:

- `operator requests timeline` is HTTP for the request but also reads the `--db`
  for the audit trail.
- `operator audit export` reads the `--db` but resolves the workspace from the
  **`--workspace-key`** (it does *not* take `--workspace-id`), so it needs both
  `--db` and the workspace key.

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

**Per-source request rate limiting (`VINCTOR_RATE_LIMIT_PER_MINUTE`):** opt-in,
**off by default**. Set it to a positive integer to cap requests per client IP per
60-second fixed window; unset, `≤0`, or unparseable leaves the limiter disabled and
behavior byte-for-byte unchanged.

```bash
VINCTOR_RATE_LIMIT_PER_MINUTE=120 vinctor service serve --host 127.0.0.1 --port 8765
```

- **Pre-auth:** the check runs at the top of every `POST`/`GET`, before routing,
  body read, or auth, so it protects the unauthenticated surface (alongside the
  request-body cap and handler timeout).
- **Over-limit response:** `429` with the generic body `{"error": "rate_limited"}`
  and a `Retry-After: 60` header — nothing else is disclosed.
- **Fail-open:** it is an availability tool, not an authz gate. If the limiter is
  disabled, errors, or its source table is full, the request proceeds.
- **Source = client IP.** By default the socket peer is always the source and
  `X-Forwarded-For` is ignored. Behind a reverse proxy, set
  `VINCTOR_TRUSTED_PROXIES` to a comma-separated list of proxy CIDRs. Forwarding
  data is honored only when the immediate peer is trusted, then walked
  right-to-left to select the rightmost non-trusted hop:

  ```bash
  VINCTOR_TRUSTED_PROXIES=127.0.0.0/8,10.0.0.0/8 \
    VINCTOR_RATE_LIMIT_PER_MINUTE=120 \
    vinctor service serve --host 127.0.0.1 --port 8765
  ```

  Never trust a broad CIDR containing direct clients. Listing a CIDR asserts
  that those proxies **append the peer address they accepted each connection
  from** to `X-Forwarded-For` (nginx: `proxy_set_header X-Forwarded-For
  $proxy_add_x_forwarded_for;` — see the
  [reverse-proxy runbook](deployment/operational-runbooks.md#tls--reverse-proxy);
  Caddy 2.5+ does the equivalent by default). A trusted proxy that forwards the
  client's header unchanged lets every request claim a fresh source, which
  turns the limiter off. The counter is per-process and in-memory (not shared
  across multiple service instances).

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
- **Consumed via** `--workspace-key` / `VINCTOR_WORKSPACE_KEY` by the HTTP
  `operator` commands (`requests`, `rules`) and the hybrid `operator audit export`;
  the direct-DB `operator` commands (`bounds`, `audit list`, `policy`, `storage`,
  `service`, `keys`, `tokens`, and the `require-*` mandates) take `--workspace-id`
  against the `--db` instead.

---

## Auditor (read-only workspace key `auk_…`)

An auditor key is workspace-scoped and can call only `GET /v1/audit-events`
and `GET /v1/audit-events/{event_id}` through `X-Auditor-Key`.

- **Created/rotated by** `vinctor operator keys rotate auditor`; the raw key is
  printed once.
- **Listed/revoked** with the same `operator keys` commands as other local keys.
- It is rejected by boundary, grant, request, rule, token, policy, and other
  mutation paths; those continue to require the workspace/operator key.
- `operator audit export` accepts it through `--auditor-key` or
  `VINCTOR_AUDITOR_KEY`.
- Authentication failures with no resolvable workspace are not returned to a
  workspace auditor, preventing cross-tenant leakage.

---

## Service operator (global key `sok_…`)

The service-operator key has one narrow global capability: reading unattributed
`auth_failed` events that cannot safely be assigned to a workspace.

```bash
vinctor operator keys rotate service-operator
vinctor --service-operator-key "$VINCTOR_SERVICE_OPERATOR_KEY" \
  operator audit auth-failures --limit 50
```

The HTTP equivalent is `GET /v1/service/audit/auth-failures` with
`X-Service-Operator-Key`. This key is not a workspace/operator or auditor
identity and cannot read workspace audit events or mutate policy and grants.

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
[Configure agents and grants guide](https://vinctor.dev/docs/getting-started/agents-and-grants).

---

## PEP key (`pep_…`) and delegated enforce

A PEP (Policy Enforcement Point / resource-server) key lets a resource server ask
Vinctor to authorize a tool call **on behalf of** a subject agent, via
`/v1/enforce/delegated`. See
[ADR 0007](decisions/0007-delegated-enforce-and-pep-identity.md).

- **Created by** `vinctor operator keys rotate pep --pep-id <id>` (prints `pep_…`
  once). Workspace-scoped.
- **Consumed via** the `X-PEP-Key` header on `POST /v1/enforce/delegated`, whose
  body asserts the subject (`workspace_id`, `agent_id`, `grant_ref`, `action`,
  `resource`). The asserted `workspace_id` is forced to the PEP key's own
  workspace, so a PEP can never authorize across workspaces.
- The mechanism authorizes against the asserted grant; it does **not** by itself
  prove the call originates from the asserted agent — identity proof is an open
  decision (ADR 0007).

---

## Subject token (`vat_…` raw token, `vtk_…` token id)

A subject token is a short-lived credential an agent mints against one of its
grants and hands to a resource server, so a delegated enforce can *prove* the
call originates from the asserted agent (ADR 0007 Model 2), not merely assert it.

**Minted by the agent** (over HTTP, `POST /v1/tokens`, authenticated by the
agent key):

```bash
vinctor agent token mint --grant-ref grt_… --audience svc-files --ttl 5m \
  --action write --resource repo/feature/README.md --pop
```

- `--grant-ref` and `--audience` are **required**; `--ttl` defaults to **300s**
  (5 minutes) and accepts the same `<n>s|m|h` / plain-seconds forms as other
  duration flags. `--action` / `--resource` optionally bind the token to a
  single call. `--pop` mints a proof-of-possession token.
- The raw token (`vat_…`) is printed **once** alongside its public id (`vtk_…`)
  and `expires_at`; it is not recoverable afterward. With `--pop`, a `pop_secret`
  is also printed once.
- **Consumed via** the `X-Subject-Token` header on `POST /v1/enforce/delegated`
  (the raw `vat_…` value); the service hashes it and never stores the raw token.

**Listed / revoked by the operator** — these run **directly on the `--db`**
(direct-DB, take `--workspace-id`; no key, no endpoint):

```bash
vinctor operator tokens list                 # lists the workspace's subject tokens
vinctor operator tokens revoke <token_id>    # the vtk_… id, not the raw vat_… token
```

---

## Subject-token / PoP / boundary hardening (`operator require-*`)

Three per-`(workspace, agent)` mandates harden enforce. All run **directly on
the `--db`** (direct-DB, take `--workspace-id`) and each has the same
`{enable, disable, show}` shape. **Each defaults to off.** A bare invocation
targets the agent from `--agent-id` (or a positional `target_agent_id`); pass
`--workspace` to set the **workspace default** instead (the per-agent value
overrides it). `--workspace` cannot be combined with an agent id.

```bash
# per agent
vinctor operator require-subject-token enable agent_ci
vinctor operator require-subject-token show   agent_ci
vinctor operator require-subject-token disable agent_ci
# workspace default (applies to agents without an explicit override)
vinctor operator require-pop enable --workspace
vinctor operator require-boundary show --workspace
```

| Mandate | What it denies (403) |
| --- | --- |
| `require-subject-token` | a delegated enforce that presents **no** usable subject token |
| `require-pop` | a **presented** subject token that is **not** proof-of-possession bound — it does *not* govern the no-token case, so it composes with `require-subject-token` |
| `require-boundary` | an enforce with no `boundary_id` (see [ADR 0009](decisions/0009-mandatory-boundary-enforcement.md)) |

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

**Revoked by** `vinctor operator grants revoke <grant_ref>` — like `operator
requests`, this is an HTTP + workspace-key call (it POSTs `/v1/grants/{ref}/revoke`
so the service authenticates and audits the revocation, returning an
`audit_event_id`). It needs `--endpoint` / `VINCTOR_ENDPOINT` and `--workspace-key`
/ `VINCTOR_WORKSPACE_KEY`.

```bash
vinctor operator grants revoke grt_…
```

> [!NOTE]
> **Grant lookup is HTTP-only — there is no CLI subcommand yet.** Call the service
> directly with the workspace key:
>
> ```bash
> # fetch a grant by ref
> curl "$VINCTOR_ENDPOINT/v1/grants/grt_…" \
>   -H "X-Workspace-Key: $VINCTOR_WORKSPACE_KEY"
> ```

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
vinctor operator policy infer --agent agent_ci --min-observations 2
vinctor operator policy versions
vinctor operator policy rollback --version 3
```

`policy infer` is propose-only. It reports enforced, observed, and simulated
evidence separately, includes mapped/unmapped and would-permit/would-deny totals,
and remains exact-scope by default. `--min-observations` removes one-off exact
pairs before optional wildcard generalization.

Each successful apply appends an immutable workspace version. Rollback restores
the selected version's issuance bounds, auto-approval rules, and explicit
require-boundary settings, then appends a new version that records the rollback
and its source. Subject-token and PoP settings are outside policy-file state and
are preserved.

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
vinctor operator audit auth-failures --limit 50  # service operator only
```

All `audit list` filters are optional. `audit export` currently supports
`--format jsonl`, and writes to stdout when `--file` is omitted.

> [!NOTE]
> `audit list` is direct-DB (takes `--workspace-id`), but `audit export` is
> **hybrid**: it reads the `--db` yet resolves the workspace from the
> `--workspace-key`, so it requires the workspace key rather than `--workspace-id`.

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

> [!NOTE]
> `operator service info` reports the **configured default port** (from the
> runtime config / `VINCTOR_PORT`), not the live port a running `service serve`
> was started with via `--port`.

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
| `agent` | `requests create`, `requests status`, `enforce`, `token mint` |
| `operator requests` | `list`, `inbox`, `timeline`, `view`, `approve`, `reject`, `evaluate` |
| `operator rules` | `create`, `list`, `disable` |
| `operator bounds` | `set`, `show` |
| `operator tokens` | `list`, `revoke` |
| `operator grants` | `revoke` |
| `operator require-subject-token` | `enable`, `disable`, `show` |
| `operator require-pop` | `enable`, `disable`, `show` |
| `operator require-boundary` | `enable`, `disable`, `show` |
| `operator audit` | `list`, `export` |
| `operator policy` | `apply`, `export` |
| `operator storage` | `backup`, `reset`, `restore`, `migrate` |
| `operator keys` | `list`, `revoke`, `rotate {workspace,agent,pep}` |
| `operator service` | `info` |
| `demo` | `check`, `service` |

Run any command with `--help` for its exact, version-specific options.
