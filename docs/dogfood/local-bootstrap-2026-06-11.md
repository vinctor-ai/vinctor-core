# Local bootstrap dogfooding - 2026-06-11

Historical note: this report captures the first dogfooding pass before the
follow-up UX fixes. Some findings below are now addressed; keep them as the
record of why the follow-up changes were made.

## Context

This report captures an agent-based dogfooding pass over the local service
bootstrap and grant UX.

Dogfooding persona:

- founder/operator
- early user trying to hand the local prototype to another boundary caller
- high scrutiny on adoption friction rather than implementation internals

Scope reviewed:

- `README.md`
- `src/vinctor_service/local_launcher.py`
- `demo/local_service_bootstrap_demo.py`
- `demo/local_service_launch_helper_demo.py`
- local HTTP enforce behavior
- durable local key storage behavior

Constraints preserved:

- No hosted service behavior.
- No production readiness claim.
- No raw workspace or agent key storage in SQLite or repo config.
- No OS keychain integration.
- No runtime hook implementation.
- `/v1/enforce` body remains strict: `grant_ref`, `action`, `resource`.

## First-run journey

The first-run path works:

```bash
.venv/bin/python -m vinctor_service.local_launcher \
  --db .vinctor-local.sqlite \
  --boundary-name claude-code-local
```

It prepares:

- local workspace id
- local agent id
- local grant ref
- SQLite grant, boundary, audit, and local key tables
- hashed local key records
- optional boundary record

It prints the key values a boundary caller needs:

```bash
export VINCTOR_ENDPOINT="http://127.0.0.1:<port>"
export VINCTOR_AGENT_KEY="aak_..."
export VINCTOR_GRANT_REF="grt_..."
export VINCTOR_WORKSPACE_KEY="wsk_..."
export VINCTOR_BOUNDARY_ID="bnd_..."
```

Operator verdict: the flow is usable, but the quickstart is too far down the
README and the terminal output should explain restart obligations more directly.

## Restart journey

The intended restart shape is:

```bash
.venv/bin/python -m vinctor_service.local_launcher \
  --db .vinctor-local.sqlite \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  --grant-ref "$VINCTOR_GRANT_REF" \
  --boundary-name claude-code-local
```

Important operator notes:

- `VINCTOR_AGENT_KEY` is required by `/v1/enforce`.
- `VINCTOR_GRANT_REF` remains part of the strict `/v1/enforce` body.
- `VINCTOR_WORKSPACE_KEY` is for workspace-scoped local/admin routes.
- `VINCTOR_BOUNDARY_ID` is optional enforce context and is sent as
  `X-Vinctor-Boundary-Id`.
- SQLite cannot recover raw keys. It stores only hashes and metadata.
- Restarting without explicit keys can create additional active key records.

Adoption blocker: a user can preserve keys correctly but still hit a deny if
the existing local grant has expired. The default grant TTL is currently
implicit unless the operator reads the launcher flags.

## Boundary-caller readiness

The service contract is close to boundary-caller-ready:

- Boundary callers can send `X-Agent-Key`.
- Boundary callers can optionally send `X-Vinctor-Boundary-Id`.
- The body stays strict: `grant_ref`, `action`, `resource`.
- Runtime-specific mapping from tool event to `action` and `resource` remains
  outside this repo.

Readiness by caller:

- Claude Code: closest, because the default sample boundary is
  `claude-code` / `pretooluse`.
- Codex: contract-ready, but needs a small caller recipe naming boundary
  labels.
- Hermes: contract-ready, but needs the same caller recipe.

This repo should not implement those runtime hooks yet.

## Findings

1. The local prototype quickstart is too buried.
   A new operator reaches architecture explanation before the runnable command.

2. The launcher output does not explain explicit-key restart clearly enough.
   It prints exports, but does not show the command that reuses them.

3. CLI help text is thin.
   Operator-facing flags should explain scope, identity, TTL, and boundary
   fields.

4. Grant expiry is hidden.
   Existing grants are reused, and the operator is not told when the local
   grant expires.

5. README lacks a copy-paste strict `/v1/enforce` caller example.
   Early boundary callers should not have to reverse-engineer the HTTP request
   from Python demos.

6. Demo fixture keys are intentionally small but look like real examples.
   They should either be labeled as fixture values or kept out of operator
   examples.

## Recommended next fixes

Short-term fixes for the next iteration:

- Add a top-level local prototype quickstart in `README.md`.
- Add a strict `/v1/enforce` curl example in `README.md`.
- Make launcher output print a restart command using explicit keys.
- Add launcher flag help text.
- Print grant expiry in launcher output.
- Label fixture keys in demos or keep generated-looking values in
  operator-facing docs.

Deferred intentionally:

- Raw key persistence in SQLite or repo config.
- Local config-file auto-reuse.
- OS keychain integration.
- Hosted credential management.
- Claude/Codex/Hermes runtime hook implementations.
- Approval workflow, sandboxing, raw interception, or provider integration.
