# Golden-path demo (`vinctor demo block`) — design

> Status: design (2026-06-25). Funnel-critical pre-promotion asset. Backlog epic
> in `docs/next-actions.md` → "Onboarding / first-run friction".

## Goal

Give a first-time viewer a single, honest, reproducible scene that shows the
Vinctor value in one command: **the same kind of action is allowed or denied by
context (grant + resource + environment), not by a denylist of scary commands.**

The output of this command is the hero asset reused across the README hero, the
Show HN demo, the anchor blog post, and the Cloud landing page (as a rendered
terminal GIF).

Non-goal: completeness. This packages parts that already exist
(`prepare_local_service`, service-issued grants, `enforce`). It adds **no new
authorization behavior** — only orchestration and human-readable narration.

## Why not obviously-dangerous commands

`rm -rf` / `git push --force` are catchable by a regex denylist, so blocking them
does not demonstrate why authorization is needed. The demo instead features
*normal-looking* actions whose danger depends entirely on context — which is
exactly what a grant/scope/boundary model decides and a denylist cannot. This is
also the same failure mode as the public incidents ("I thought I was in
staging").

## Scenario (the 3 beats)

The demo agent holds one grant:

```
grant scopes:  send:net/internal/*,  deploy:staging/*
```

Each beat calls the existing `/v1/enforce` path against the bootstrap grant and
reports the real decision:

| # | action | resource | decision | why |
|---|---|---|---|---|
| 1 | `send` | `net/internal/orders-api` | **permit** | within `send:net/internal/*` |
| 2 | `send` | `net/external/pastebin.com` | **deny** | same fetch, external destination — outside grant (exfil) |
| 3 | `deploy` | `production/web` | **deny** | granted `deploy:staging/*`, never production ("I thought I was in staging") |

Beat 1 is the ALLOW that proves Vinctor is not just a blocker; beats 2–3 are the
DENY hero frames. Beats 1 and 2 are the *same* `send` action separated only by
destination, making "context decided" visible in one pair.

## Command surface

```
vinctor demo block            # human-readable narration
vinctor --json demo block     # structured object (decisions + audit ids)
```

Registered alongside the existing `demo check` / `demo service` subcommands in
`_add_demo_commands`.

## Output format (human)

```
$ vinctor demo block
▸ Vinctor running. this agent's grant:  send:net/internal/*,  deploy:staging/*
  the SAME action is allowed or denied by context — this is not a denylist.

▸ agent fetches  net/internal/orders-api
  ✅ ALLOW   send:net/internal/orders-api — within grant

▸ agent fetches  net/external/pastebin.com
  🛑 DENY    send:net/external/pastebin.com — outside grant     audit ✓ evt_…
            same fetch, external destination (exfil)

▸ agent runs     deploy → production/web
  🛑 DENY    deploy:production/web — outside grant               audit ✓ evt_…
            granted deploy:staging/*, never production

▸ 3 decisions · 3 audit records · nothing out-of-scope ran.
  Vinctor authorizes mediated tool calls; it is not a sandbox.
```

The `--json` body returns: `ok`, `endpoint`, per-beat `{action, resource,
decision, reason, audit_event_id}`, and `audit_event_count`.

## Honesty guardrails

- The footer states "authorizes mediated tool calls; it is not a sandbox",
  consistent with existing repo labeling.
- The demo shows the **authorization decision**. The classification step
  (mapping a raw tool call → `action:resource`) is the runtime hook's job; the
  `(action, resource)` pairs here are supplied directly. A caption notes this so
  the demo does not imply the classifier ran.

## Implementation approach (mirrors `_demo_service`)

1. `prepare_local_service(LocalLaunchConfig(..., scopes=("send:net/internal/*",
   "deploy:staging/*"), grant_ref="grt_bootstrap"))` in a `TemporaryDirectory`.
2. Start the server thread.
3. For each beat, `POST /v1/enforce` with `_agent_headers` and
   `{grant_ref: "grt_bootstrap", action, resource}`; capture `decision` and
   (on deny) `reason`.
4. After each enforce, read the latest `handle.service.audit_events[-1]` for the
   `event_id` / `event_type`.
5. Build the body and emit via `_emit` with a `_demo_block_text` renderer.
6. `finally`: shutdown server, join thread, `handle.close()`.

No grant-request/approval dance is needed — enforce runs directly against the
scoped bootstrap grant for a tight, legible scene.

## Testing

A test mirroring existing demo tests: run `demo block` with `--json`, assert
beat 1 `permit`, beats 2–3 `deny`, and `audit_event_count == 3`. Pin the
deny reasons so the narration copy stays truthful.

## GIF rendering (the hero asset)

> Decision (2026-06-25): the **hero GIF runs the real CLI step by step**, not the
> `vinctor demo block` wrapper. Showing actual commands a developer could type —
> with each result appearing as it runs — is more credible than a single canned
> command. The `demo block` wrapper stays in the codebase as a one-shot smoke /
> `make demo`-style check.

Rendered deterministically with `vhs` (committed `.tape`) so it is reproducible
and version-controlled. Asset lives in `docs/assets/` (next to spec + code):

- `docs/assets/golden-path-demo.tape` — the script (assumes `vinctor` on PATH).
- `docs/assets/golden-path-demo.gif` — the rendered output.

The recorded sequence (all real commands):

1. `vinctor local start --db demo.sqlite --port 0 --scope 'send:net/internal/*'
   --scope 'deploy:staging/*' --boundary-name claude-code-local > vinctor.env &`
   then `source vinctor.env` — boots a local service with a staging-scoped grant.
   (`--port 0` picks a free port so the demo never collides.)
2. `vinctor agent enforce --action send --resource net/internal/orders-api`
   → `permit …` (within grant).
3. `vinctor agent enforce --action send --resource net/external/pastebin.com`
   → `deny …` with `scope … not covered by grant` (same fetch, external = exfil).
4. `vinctor agent enforce --action deploy --resource production/web`
   → `deny …` (granted `deploy:staging/*`, never production).

Render: `vhs golden-path-demo.tape`. Live Claude Code capture (V2) is deferred.
