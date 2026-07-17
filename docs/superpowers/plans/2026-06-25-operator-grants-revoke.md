# operator grants revoke CLI (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Add an `operator grants revoke <grant_ref>` CLI subcommand so an operator
can revoke a grant from the CLI (today revoke is HTTP-only). Mirrors the existing
HTTP operator pattern (`operator requests`) exactly: `_request_json` + `X-Workspace-Key`
+ `_raise_for_status` + `_emit`. It PROXIES the existing `POST /v1/grants/{ref}/revoke`
endpoint — no new HTTP surface, no service change.

**Scope (locked):** ONLY `revoke` (the requested command). `list`/`view`/`issue`
are deliberately out of scope. `--endpoint` / `--workspace-key` are already global
args (root `_parser()`), so the new subparser inherits them.

Repo `/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/operator-grants-revoke`, main human-merge-only. Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. stdlib only;
`ruff check` only.

---

### Task 1: `operator grants revoke`

**Files:** `src/vinctor_service/cli.py` (subparser in `_add_operator_commands`;
dispatch in `_operator`; new `_operator_grants` handler); test `tests/test_cli.py`.

- [ ] **Step 1 — failing tests** (mirror the existing live-in-process `operator
  requests`/`approve` CLI tests; use the same `common` endpoint+workspace-key
  fixture + `_run` helper):
  - issue/obtain a grant, run `operator grants revoke <grant_ref>` → exit 0; output
    (and JSON body) includes the grant_ref + `audit_event_id`; a subsequent
    `agent enforce` on that grant → DENY with the "is revoked" reason.
  - `operator grants revoke <unknown_grant_ref>` → a clean `CliError` (the endpoint
    404 surfaced via `_raise_for_status`), nonzero exit, NO traceback.
  - `operator grants revoke <ref>` with no workspace key → clean
    `workspace key is required` error.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — subparser** (in `_add_operator_commands`, add after the `tokens`
  block):

```python
    grants = resources.add_parser("grants")
    grant_commands = grants.add_subparsers(dest="grants_command", required=True)
    revoke_grant = grant_commands.add_parser("revoke")
    revoke_grant.add_argument("grant_ref")
```

- [ ] **Step 4 — dispatch** (in `_operator`, add after the `tokens` branch):

```python
    if resource == "grants":
        _operator_grants(args, stdout=stdout)
        return
```

- [ ] **Step 5 — handler** (mirror `_operator_requests`' approve/reject branch):

```python
def _operator_grants(args: argparse.Namespace, *, stdout: TextIO) -> None:
    command = args.grants_command
    if command == "revoke":
        status, body = _request_json(
            args.endpoint,
            "POST",
            f"/v1/grants/{args.grant_ref}/revoke",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        _emit(
            args,
            body,
            f"revoked grant {body.get('grant_ref', args.grant_ref)} "
            f"status={body.get('status', '-')} "
            f"audit_event_id={body.get('audit_event_id', '-')}",
            stdout=stdout,
        )
        return
    raise CliError(f"unknown grants command: {command}")
```

  (Match the existing CLI's no-path-encoding convention — the sibling
  `_operator_requests` interpolates `request_id` directly; `grant_ref` is a safe
  `grt_…` token. Keep style identical to the sibling handlers.)

- [ ] **Step 6 — run tests + full suite + ruff; commit** `feat(cli): operator grants revoke`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green.
- [ ] Update `docs/cli-reference.md`: replace the "grant revoke is HTTP-only / no CLI
  yet" note with the new `operator grants revoke` command (HTTP + workspace-key,
  hybrid like `operator requests`); add it to the command index. (`docs/next-actions`
  if it lists the gap.) Fold into the PR.
- [ ] Push branch, open PR (no merge; controller auto-merges after a final
  adversarial review per the march agreement).

## Notes
- Revoke is HTTP + workspace-key (operator credential), like `operator requests` —
  NOT direct-DB. The service authenticates + audits the revocation (returns
  `audit_event_id`).
- Keep it to `revoke` only. The read companions (`list`/`view`) and `issue` are
  intentionally not added in this slice.
