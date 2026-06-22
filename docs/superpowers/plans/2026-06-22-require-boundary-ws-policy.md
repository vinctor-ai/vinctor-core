# require_boundary — workspace-default + policy-file surface (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Extend the shipped per-agent `require_boundary` (ADR 0009-B) with a
**workspace-default + per-agent override** resolution and a **policy-file**
surface, keeping default-off byte-for-byte unchanged.

**Design (decisions locked):**
- **Storage:** reuse `agent_enforcement_settings` (no schema change). A
  workspace-default is the row with **`agent_id = ""`** (the per-agent CLI/policy
  always uses a non-empty agent id, so `""` is a safe reserved key).
- **Resolution / full override:** distinguish *absent* from *explicit-false* so a
  per-agent row can both escalate AND exempt. Add
  `get_require_boundary_setting(ws, agent) -> bool | None` (None = no row) and
  `is_boundary_required(ws, agent) -> bool` = **agent row if present, else
  workspace-default (`agent_id=""`) row if present, else False**. The enforce
  contracts call `is_boundary_required` (not `get_require_boundary`).
- **CLI:** `operator require-boundary enable|disable|show` gains `--workspace`
  (operates on the `agent_id=""` row).
- **Policy file:** optional top-level `require_boundary: { workspace: <bool>,
  agents: [<id>...] }`; apply enables (additive); export emits the current state.

**Invariants:** default-off (no rows) → `is_boundary_required` False → unchanged.
`get_require_boundary` (the existing bool getter) stays for back-compat; the new
nullable getter drives resolution. Repo from `/Users/taeheon/dev/agent-authority/vinctor-core`,
venv `.venv/bin/...`, branch `feat/require-boundary-ws-policy`, main human-merge-only.
Commit trailer ends with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: ws-default + agent-override resolution (repo + contracts)

**Files:** `src/vinctor_service/repositories.py`, `src/vinctor_service/sqlite.py`,
`src/vinctor_service/v1_enforce.py`; test `tests/test_require_boundary.py`.

- [ ] **Step 1 — failing tests** (append to `tests/test_require_boundary.py`):

```python
def test_ws_default_hardens_agent_without_own_row() -> None:
    svc = _svc()
    svc.agent_enforcement_settings_repository.set_require_boundary(
        workspace_id="ws", agent_id="", require_boundary=True, now=NOW)
    r = svc.enforce(V1EnforceRequest(workspace_id="ws", agent_id="a", grant_ref="grt",
                                     action="write", resource="repo/x/y"), now=NOW)
    assert r.status_code == 403 and r.decision == "deny"


def test_agent_row_overrides_ws_default_to_exempt() -> None:
    svc = _svc()
    repo = svc.agent_enforcement_settings_repository
    repo.set_require_boundary(workspace_id="ws", agent_id="", require_boundary=True, now=NOW)
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=False, now=NOW)
    r = svc.enforce(V1EnforceRequest(workspace_id="ws", agent_id="a", grant_ref="grt",
                                     action="write", resource="repo/x/y"), now=NOW)
    assert r.decision == "permit"


def test_no_rows_is_not_required() -> None:
    repo = _svc().agent_enforcement_settings_repository
    assert repo.is_boundary_required(workspace_id="ws", agent_id="a") is False
    repo.set_require_boundary(workspace_id="ws", agent_id="", require_boundary=True, now=NOW)
    assert repo.is_boundary_required(workspace_id="ws", agent_id="a") is True
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=False, now=NOW)
    assert repo.is_boundary_required(workspace_id="ws", agent_id="a") is False
```

- [ ] **Step 2 — run, expect FAIL** (`AttributeError: is_boundary_required`).

- [ ] **Step 3 — Protocol** (`repositories.py`, add to `AgentEnforcementSettingsRepository`):

```python
    def get_require_boundary_setting(self, *, workspace_id: str, agent_id: str) -> bool | None: ...

    def is_boundary_required(self, *, workspace_id: str, agent_id: str) -> bool: ...
```

- [ ] **Step 4 — InMemory** (`repositories.py`, in `InMemoryAgentEnforcementSettingsRepository`):

```python
    def get_require_boundary_setting(self, *, workspace_id: str, agent_id: str) -> bool | None:
        return self._require_boundary.get((workspace_id, agent_id))

    def is_boundary_required(self, *, workspace_id: str, agent_id: str) -> bool:
        agent = self._require_boundary.get((workspace_id, agent_id))
        if agent is not None:
            return agent
        return self._require_boundary.get((workspace_id, ""), False)
```

- [ ] **Step 5 — SQLite** (`sqlite.py`, in `SQLiteAgentEnforcementSettingsRepository`):

```python
    def get_require_boundary_setting(self, *, workspace_id: str, agent_id: str) -> bool | None:
        row = self._conn.execute(
            "SELECT require_boundary FROM agent_enforcement_settings "
            "WHERE workspace_id = ? AND agent_id = ?",
            (workspace_id, agent_id),
        ).fetchone()
        return bool(row[0]) if row is not None else None

    def is_boundary_required(self, *, workspace_id: str, agent_id: str) -> bool:
        agent = self.get_require_boundary_setting(workspace_id=workspace_id, agent_id=agent_id)
        if agent is not None:
            return agent
        ws = self.get_require_boundary_setting(workspace_id=workspace_id, agent_id="")
        return ws if ws is not None else False
```

- [ ] **Step 6 — contracts use the resolver.** In `src/vinctor_service/v1_enforce.py`,
  the two `agent_enforcement_settings_repository.get_require_boundary(` calls
  (the direct contract ~line 79 and the delegated ~line 247) become
  `...is_boundary_required(`. Same kwargs (`workspace_id=`, `agent_id=`).

- [ ] **Step 7 — run tests + full suite + ruff; commit** `feat(require-boundary): workspace-default + per-agent override resolution`.

---

### Task 2: CLI `--workspace` mode

**Files:** `src/vinctor_service/cli.py`; test `tests/test_cli.py`.

- [ ] **Step 1 — failing test** (`tests/test_cli.py`, mirror the existing
  `require_boundary` CLI test):

```python
def test_vinctor_cli_require_boundary_workspace_default(tmp_path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]
    enabled = _run([*common, "operator", "require-boundary", "enable", "--workspace"])
    shown = _run([*common, "operator", "require-boundary", "show", "--workspace"])
    assert enabled["require_boundary"] is True and enabled["scope"] == "workspace"
    assert shown["require_boundary"] is True
```

- [ ] **Step 2 — run, expect FAIL** (unknown `--workspace`).

- [ ] **Step 3 — add `--workspace` to each subcommand** (in `_add_operator_commands`,
  the `require-boundary` enable/disable/show parsers): `add_argument("--workspace",
  action="store_true")`.

- [ ] **Step 4 — handler** (`_operator_require_boundary`): resolve the target —
  `agent_id = "" if args.workspace else (args.target_agent_id or args.agent_id)`;
  the emitted body adds `"scope": "workspace" if args.workspace else "agent"`.
  Reject the ambiguous case (both `--workspace` and a positional agent) with a
  `CliError`. Keep the existing per-agent behavior unchanged when `--workspace`
  is absent.

- [ ] **Step 5 — run test + full suite + ruff; commit** `feat(require-boundary): operator require-boundary --workspace default`.

---

### Task 3: policy-file `require_boundary` section

**Files:** `src/vinctor_service/policy_files.py`,
`src/vinctor_service/repositories.py` + `sqlite.py` (a list accessor for export);
test `tests/test_cli.py` (policy apply/export) and/or `tests/test_policy_files.py`.

- [ ] **Step 1 — list accessor for export.** Add to the settings repo (Protocol +
  InMemory + SQLite): `list_require_boundary(workspace_id) -> tuple[tuple[str, bool], ...]`
  returning every `(agent_id, value)` row for the workspace (including the
  `agent_id=""` workspace-default). SQLite: `SELECT agent_id, require_boundary
  FROM agent_enforcement_settings WHERE workspace_id = ? ORDER BY agent_id`.
  InMemory: filter `self._require_boundary` by workspace.

- [ ] **Step 2 — failing test** (apply→export round-trip). Author a policy YAML with:

```yaml
require_boundary:
  workspace: true
  agents: [agent_runner]
```

  apply it, then assert `service.agent_enforcement_settings_repository
  .is_boundary_required(workspace_id="ws_demo", agent_id="agent_runner")` is True
  and the `agent_id=""` row is True; then `export` and assert the emitted
  `require_boundary` block round-trips (`workspace: true`, `agents` contains
  `agent_runner`).

- [ ] **Step 3 — allow the field.** In `_load_policy_document`, add
  `"require_boundary"` to the allowed top-level set (currently `{"version",
  "workspace_id", "agent_bounds", "auto_approval_rules"}`).

- [ ] **Step 4 — parse + apply.** Add `_parse_require_boundary(document) ->
  dict` validating an optional mapping `{workspace?: bool, agents?: [non-empty
  str]}` (reject unknown keys / wrong types with `ValueError`, consistent with
  the other `_parse_*`). In `apply_policy_file`, parse it in the upfront
  validation phase (so apply stays all-or-nothing), then in the write phase: if
  `workspace` is present, `set_require_boundary(workspace_id, agent_id="",
  require_boundary=<workspace>, now=now)`; for each agent in `agents`,
  `set_require_boundary(workspace_id, agent_id=<agent>, require_boundary=True,
  now=now)`. (Disabling a per-agent flag stays a CLI action; document that the
  policy section enables.)

- [ ] **Step 5 — export.** In `export_policy_document`, add a `require_boundary`
  block built from `list_require_boundary(workspace_id)`: `workspace` = the
  `agent_id=""` row's value if present (omit the key otherwise), `agents` = the
  sorted non-empty agent ids whose value is True. Omit the whole block if there
  are no rows (keep exports of unhardened workspaces unchanged).

- [ ] **Step 6 — run tests + full suite + ruff; commit** `feat(require-boundary): policy-file require_boundary apply/export`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green.
- [ ] Push branch, open PR (no merge). PR body summarizes ws-default+override +
  policy-file, notes default-off unchanged and the full-override semantics.

## Notes
- Full override means a per-agent row of **False** exempts an agent even when the
  workspace-default is True — that is the point of "override". This is why
  resolution must distinguish absent (`None`) from explicit `False`.
- Default-off regression must stay: no rows → `is_boundary_required` False. Keep
  the existing default-off tests passing.
