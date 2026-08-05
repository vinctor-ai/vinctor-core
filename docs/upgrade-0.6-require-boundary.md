# Upgrading to 0.6.0: turning on the boundary mandate

0.6.0 makes `require_boundary` default **on** — but **only for databases created
by 0.6.0**. If you are upgrading, nothing changed for you, and that is the point
of this note: the release notes tell you the migration does not turn the mandate
on, and then stop. This tells you how to find out what your database actually
does today, and how to move it.

Skip this if you already run `operator require-boundary enable` for every agent.

## If you run Postgres, read this first

**`require-boundary` cannot be managed from the CLI on Postgres at all.** Every
`enable`/`disable`/`show` command below opens a SQLite file directly through
`--db`. There is no Postgres code path, no HTTP route, and no MCP tool for this
setting. `--endpoint` is accepted by the command and then ignored — pointing it
at a running service does not make it talk to that service:

```bash
vinctor --endpoint http://127.0.0.1:9999 operator require-boundary show agent_local
# error: db is required
```

The `--db` flag's own help text is explicit: *"SQLite database path for
direct-DB operator commands."*

This is not a scoping choice in this document. Postgres is the recommended
production topology, so the operator most exposed to a silent posture difference
is the one this control cannot reach. Concretely, on Postgres:

- **You can read your posture.** The three layers and the create-once problem are
  the same as SQLite — Postgres's `CREATE TABLE IF NOT EXISTS` likewise never
  rewrites an existing table, so a database first created before 0.6.0 keeps
  `DEFAULT FALSE`. This is the query the service itself uses to read that
  default; `true` means created by 0.6.0 or later, `false` means upgraded:

  ```sql
  SELECT column_default
  FROM information_schema.columns
  WHERE table_schema = current_schema()
    AND table_name = 'agent_enforcement_settings'
    AND column_name = 'require_boundary';
  ```

  The overrides that outrank it:

  ```sql
  SELECT workspace_id, agent_id, require_boundary
  FROM agent_enforcement_settings
  WHERE require_boundary_set;
  ```

- **You cannot change it through any supported interface.** The only route is
  direct `UPDATE`/`INSERT` against `agent_enforcement_settings`.
- **Direct SQL leaves no control-plane audit record.** Every mandate change made
  through the supported path writes an `enforcement_setting_changed` event in the
  same transaction as the change. Hand-written SQL changes the effective posture
  and adds nothing to `audit_events`, so the change is invisible to
  `operator audit` and to anyone reviewing who hardened or exempted an agent.

If you run Postgres, treat the rest of this note as background on the resolution
model, and treat closing that gap as a prerequisite before you rely on this
control. Track it with PKA-179 item 3.

## Why an upgrade cannot just flip it

`X-Vinctor-Boundary-Id` is caller-controlled. With the mandate off, an enforce
call that simply omits the header is permitted — so an operator who disabled a
boundary as an emergency stop has stopped nothing (PKA-179).

Turning it on for an existing deployment would deny **every PEP that does not
send the header**, including ones working correctly right now. That is an
outage, applied silently by an upgrade, to fix a problem the operator has not
been told about yet. So the migration leaves your database alone and this note
exists instead.

## Step 1 — find out what you have

The effective answer is resolved in three layers, first match wins:

1. an **agent** override, if one was ever set for that agent;
2. a **workspace** override (stored with an empty `agent_id`);
3. the **schema default of the `require_boundary` column** in your database.

Layer 3 is the one the upgrade does not touch. SQLite's
`CREATE TABLE IF NOT EXISTS` never alters an existing table, so a database first
created by 0.5.x keeps `DEFAULT 0` forever, no matter which version opens it.

Read the layer-3 default directly:

```bash
sqlite3 .vinctor-local.sqlite \
  "SELECT dflt_value FROM pragma_table_info('agent_enforcement_settings') WHERE name='require_boundary';"
# 1
```

- `0` → an upgraded database. Any agent with no override is **not** required to
  send a boundary id.
- `1` → created by 0.6.0 or later. Agents with no override are required.

Then read the overrides, which win over that default:

```bash
sqlite3 .vinctor-local.sqlite \
  "SELECT workspace_id, agent_id, require_boundary FROM agent_enforcement_settings WHERE require_boundary_set = 1;"
# ws_local||1
```

An empty `agent_id` is the workspace-wide row. No rows means no overrides exist
and the column default above is what every agent gets.

The supported command for a single agent — use this rather than SQL when you can,
since it applies the same three-layer resolution the enforce path uses:

```bash
vinctor --db .vinctor-local.sqlite operator require-boundary show agent_local
# require_boundary workspace=ws_local agent=agent_local value=True
```

The agent id is positional. For the workspace-wide row, pass the `--workspace`
flag instead of an agent id (it takes no value; the workspace comes from
`--workspace-id` or the local default):

```bash
vinctor --db .vinctor-local.sqlite operator require-boundary show --workspace
# require_boundary workspace=ws_local agent= value=True
```

The two cannot be combined:

```bash
vinctor --db .vinctor-local.sqlite operator require-boundary show --workspace agent_local
# error: require-boundary --workspace cannot be combined with an agent id
```

> **On 0.6.0 as released, `show <agent>` does not account for the workspace
> override.** It reads the agent's own override and then falls straight through
> to the column default, skipping layer 2. So on an upgraded database, after you
> enable the mandate workspace-wide in step 3, `show agent_local` still prints
> `value=False` even though enforce is denying — and on a fresh 0.6.0 database a
> workspace-wide `disable` leaves it printing `value=True` while enforce permits.
> This is fixed in 0.7.0; `show` now reports the same effective value enforce
> computes. On 0.6.0 itself, use step 4 rather than `show` to confirm posture.

## Step 2 — find out who would break

Enabling the mandate denies any PEP that does not send `X-Vinctor-Boundary-Id`.
Before enabling, confirm each agent's PEP sends it — the boundary id is what the
adapter reads from `VINCTOR_BOUNDARY_ID`, so an agent whose environment does not
set that variable is one that will start failing.

The cheap check is to look at your audit records for enforce calls carrying no
boundary id. Those are exactly the callers that will be denied.

## Step 3 — roll it out per agent, then per workspace

Per agent first, so a mistake costs one agent rather than all of them:

```bash
vinctor --db .vinctor-local.sqlite operator require-boundary enable agent_local
# require_boundary workspace=ws_local agent=agent_local value=True
```

Verify the agent still works, then widen to the workspace:

```bash
vinctor --db .vinctor-local.sqlite operator require-boundary enable --workspace
# require_boundary workspace=ws_local agent= value=True
```

The setting is read per enforce call, so it takes effect on a running service
with no restart — and so does rolling it back:

```bash
vinctor --db .vinctor-local.sqlite operator require-boundary disable agent_local
# require_boundary workspace=ws_local agent=agent_local value=False
```

## Step 4 — confirm it is actually on

Do not take the command's output as proof; make the call the mandate is supposed
to deny. This tests the whole path — resolution, the running service, and the
PEP's headers — rather than one command's reading of one row:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' "$VINCTOR_ENDPOINT/v1/enforce" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: $VINCTOR_AGENT_KEY" \
  -d "{\"grant_ref\":\"$VINCTOR_GRANT_REF\",\"action\":\"write\",\"resource\":\"repo/feature/readme\"}"
# 403
```

```text
enforce WITHOUT X-Vinctor-Boundary-Id  →  403  {"decision":"deny","error":"boundary_required"}
enforce WITH    X-Vinctor-Boundary-Id  →  200  (normal decision)
```

If the first still returns `200`, an override is winning over what you set —
re-read step 1, checking the agent row before the workspace row.

## Known limits

- **`require-boundary` is settable only through `--db`, and `--db` is SQLite.**
  There is no HTTP route and no MCP tool, and `--endpoint` is ignored. An
  operator without filesystem access to a SQLite deployment — or running Postgres
  at all — cannot turn it on through any supported interface (PKA-179, item 3).
  See the Postgres section above.
- **A fresh database is not a migrated one.** If you would rather have 0.6.0's
  default than a documented rollout, the only supported way to get the `1`
  column default is a database created by 0.6.0. Enabling the workspace override
  gets you the same effective posture without recreating anything, and is what
  this note recommends.
