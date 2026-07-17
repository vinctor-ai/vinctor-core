# ADR 0009-B — per-agent `require_boundary` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator mark a specific agent `require_boundary`; when set, an `/v1/enforce` (direct or delegated) request for that agent with a **truly-absent** boundary (`X-Vinctor-Boundary-Id` not sent → `boundary_id is None`) fails closed with `boundary_required` instead of permitting on grant scope. Default off → existing behavior byte-for-byte unchanged.

**Architecture:** A new per-agent `agent_enforcement_settings` table + repository (mirrors the `SubjectTokenRepository` pattern). The PDP core stays identity-agnostic: `EnforceInput` gains `require_boundary: bool`, and `_resolve_boundary`'s existing `boundary_id is None` branch denies (`boundary_required`) when the flag is set. The service layer resolves the per-agent flag and passes it down through the single `EnforceInput` constructor `_evaluate_and_record`. A direct-DB operator CLI toggles the flag.

**Tech Stack:** Python 3.11, sqlite3, dataclasses, argparse; pytest; `ruff check` (repo does NOT enforce `ruff format`).

**Source of truth:** `docs/superpowers/specs/2026-06-22-adr0009-require-boundary-design.md`.

**Conventions:** run from `/Users/taeheon/dev/agent-authority/vinctor-core`; venv `.venv/bin/python -m pytest` / `.venv/bin/ruff check`; branch `feat/adr0009-require-boundary` (checked out, spec committed). Do NOT merge to main. Commit message MUST end with a blank line then:
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`

**Critical invariants (from the adversarial review — do not regress):**
- **Default-off = byte-for-byte unchanged.** `get_require_boundary` returns False with no row.
- **Only the truly-absent (`None`) case changes.** Do NOT normalize empty/whitespace `boundary_id` to `None`; an empty header already denies `boundary_not_found` and must keep doing so (flag on or off).
- **Dropped-repo is fail-open** → pin the wiring with a **flag-ON service test on BOTH the direct and delegated paths**.
- `_evaluate_and_record` (v1_enforce.py) is the single `EnforceInput` constructor.

---

### Task 1: `agent_enforcement_settings` table + repository + schema v4 + wiring

**Files:**
- Modify: `src/vinctor_service/repositories.py` (Protocol + InMemory twin)
- Modify: `src/vinctor_service/sqlite.py` (table + v4 row + SQLite twin + service field)
- Modify: `src/vinctor_service/in_memory.py` (service field)
- Modify: `src/vinctor_service/__init__.py` (exports)
- Test: `tests/test_agent_enforcement_settings_repository.py` (new)
- Modify (cross-cutting): the schema-version assertions (see Step 8)

- [ ] **Step 1: Write the failing repository test**

Create `tests/test_agent_enforcement_settings_repository.py`:

```python
import sqlite3
from datetime import UTC, datetime

from vinctor_service import (
    InMemoryAgentEnforcementSettingsRepository,
    SQLiteAgentEnforcementSettingsRepository,
)
from vinctor_service.sqlite import get_sqlite_schema_versions, init_sqlite_schema

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def test_in_memory_default_false_and_set_get() -> None:
    repo = InMemoryAgentEnforcementSettingsRepository()
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is False
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=True, now=NOW)
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is True
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=False, now=NOW)
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is False


def test_sqlite_default_false_and_round_trip(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = SQLiteAgentEnforcementSettingsRepository(conn)
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is False
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=True, now=NOW)
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is True


def test_sqlite_schema_records_version_4(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    assert get_sqlite_schema_versions(conn) == (1, 2, 3, 4)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_agent_enforcement_settings_repository.py -q`
Expected: FAIL — `ImportError: cannot import name 'InMemoryAgentEnforcementSettingsRepository'`.

- [ ] **Step 3: Add the Protocol + in-memory twin**

In `src/vinctor_service/repositories.py`: ensure `from datetime import datetime` is imported (add if absent), then add (next to `SubjectTokenRepository`):

```python
class AgentEnforcementSettingsRepository(Protocol):
    def get_require_boundary(self, *, workspace_id: str, agent_id: str) -> bool: ...

    def set_require_boundary(
        self, *, workspace_id: str, agent_id: str, require_boundary: bool, now: datetime
    ) -> None: ...


class InMemoryAgentEnforcementSettingsRepository:
    def __init__(self) -> None:
        self._require_boundary: dict[tuple[str, str], bool] = {}

    def get_require_boundary(self, *, workspace_id: str, agent_id: str) -> bool:
        return self._require_boundary.get((workspace_id, agent_id), False)

    def set_require_boundary(
        self, *, workspace_id: str, agent_id: str, require_boundary: bool, now: datetime
    ) -> None:
        self._require_boundary[(workspace_id, agent_id)] = require_boundary
```

- [ ] **Step 4: Add the SQLite table + v4 row + repo**

In `src/vinctor_service/sqlite.py`, inside `init_sqlite_schema`'s `executescript` block (next to the other `CREATE TABLE` statements, e.g. after `subject_tokens`):

```sql
CREATE TABLE IF NOT EXISTS agent_enforcement_settings (
    workspace_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    require_boundary INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, agent_id)
);
```

Then, immediately after the version-3 `INSERT OR IGNORE INTO schema_migrations` row and before `conn.commit()`:

```python
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (4, datetime.now(UTC).isoformat()),
    )
```

Add the repository class (mirror the scope-bounds upsert):

```python
class SQLiteAgentEnforcementSettingsRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def get_require_boundary(self, *, workspace_id: str, agent_id: str) -> bool:
        row = self._conn.execute(
            """
            SELECT require_boundary FROM agent_enforcement_settings
            WHERE workspace_id = ? AND agent_id = ?
            """,
            (workspace_id, agent_id),
        ).fetchone()
        return bool(row[0]) if row is not None else False

    def set_require_boundary(
        self, *, workspace_id: str, agent_id: str, require_boundary: bool, now: datetime
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO agent_enforcement_settings (
                    workspace_id, agent_id, require_boundary, updated_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(workspace_id, agent_id) DO UPDATE SET
                    require_boundary = excluded.require_boundary,
                    updated_at = excluded.updated_at
                """,
                (workspace_id, agent_id, 1 if require_boundary else 0, now.isoformat()),
            )
```

- [ ] **Step 5: Wire the repo field onto both services**

In `src/vinctor_service/sqlite.py` `SQLiteV1Service`: add the class-body declaration (next to `subject_token_repository`):

```python
    agent_enforcement_settings_repository: SQLiteAgentEnforcementSettingsRepository = field(init=False)
```

and in `__post_init__` (after `self.subject_token_repository = ...`):

```python
        self.agent_enforcement_settings_repository = SQLiteAgentEnforcementSettingsRepository(self.conn)
```

In `src/vinctor_service/in_memory.py`: add `InMemoryAgentEnforcementSettingsRepository` to the `from vinctor_service.repositories import (...)` block, and in `__post_init__` (next to `self.subject_token_repository = ...`):

```python
        self.agent_enforcement_settings_repository = InMemoryAgentEnforcementSettingsRepository()
```

- [ ] **Step 6: Export the new symbols**

In `src/vinctor_service/__init__.py`: add `AgentEnforcementSettingsRepository`, `InMemoryAgentEnforcementSettingsRepository` to the `repositories` import block, `SQLiteAgentEnforcementSettingsRepository` to the `sqlite` import block, and all three to `__all__` (alphabetized).

- [ ] **Step 7: Run the repository test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_agent_enforcement_settings_repository.py -q`
Expected: PASS (3 tests).

- [ ] **Step 8: Bump ALL schema-version assertions (cross-cutting)**

The v4 row breaks existing assertions. Run `grep -rn '(1, 2, 3)\|\[1, 2, 3\]\|schema_version' tests/` and bump each NON-empty-DB assertion to include 4 (leave the `None` / `[]` empty-DB cases at `test_cli.py:562-563` and `test_storage_ops.py:118/131` untouched):
- `tests/test_subject_token_repository.py:47` `(1, 2, 3)` → `(1, 2, 3, 4)`; rename the test `test_sqlite_schema_records_version_3` → `_4`.
- `tests/test_storage_ops.py` lines 61, 98, 114, 125, 144, 163, 180, 189, 198: `(1, 2, 3)` → `(1, 2, 3, 4)`.
- `tests/test_cli.py`: lines 400, 470, 474, 547, 583, 661 `[1, 2, 3]` → `[1, 2, 3, 4]`; lines 401, 546 `schema_version"] == 3` → `== 4`.

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src/ tests/`
Expected: all pass, ruff clean.

- [ ] **Step 9: Commit**

```bash
git add src/vinctor_service/repositories.py src/vinctor_service/sqlite.py src/vinctor_service/in_memory.py src/vinctor_service/__init__.py tests/test_agent_enforcement_settings_repository.py tests/test_subject_token_repository.py tests/test_storage_ops.py tests/test_cli.py
git commit -m "feat(require-boundary): agent_enforcement_settings repository + schema v4"
```

---

### Task 2: `EnforceInput.require_boundary` + `_resolve_boundary` deny (core)

**Files:**
- Modify: `src/vinctor_core/models.py` (`EnforceInput`)
- Modify: `src/vinctor_core/enforce.py` (`_resolve_boundary`)
- Test: `tests/test_require_boundary.py` (new)

- [ ] **Step 1: Write the failing core test**

Create `tests/test_require_boundary.py`:

```python
from datetime import UTC, datetime, timedelta

from vinctor_core.enforce import evaluate_enforce
from vinctor_core.models import EnforceInput, Grant

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _grant() -> Grant:
    return Grant(
        grant_id="g", grant_ref="grt", workspace_id="ws", agent_id="a",
        scopes=("write:repo/x/*",), status="active", expires_at=NOW + timedelta(hours=1),
    )


def _input(**over) -> EnforceInput:
    kwargs = dict(grant=_grant(), action="write", resource="repo/x/y", now=NOW)
    kwargs.update(over)
    return EnforceInput(**kwargs)


def test_require_boundary_absent_denies_boundary_required() -> None:
    d = evaluate_enforce(_input(require_boundary=True))
    assert d.decision == "deny"
    assert d.reason == "boundary_required"
    assert d.attempted_boundary_id is None


def test_require_boundary_off_absent_permits() -> None:
    d = evaluate_enforce(_input())
    assert d.decision == "permit"


def test_require_boundary_on_empty_header_still_boundary_not_found() -> None:
    # Empty/whitespace header is NOT absent — it must keep denying boundary_not_found,
    # not flip to boundary_required (and definitely not permit).
    d = evaluate_enforce(_input(boundary_id="", require_boundary=True))
    assert d.decision == "deny"
    assert d.reason == "boundary_not_found"


def test_require_boundary_off_empty_header_denies_boundary_not_found() -> None:
    # Regression: empty header on the default-off path keeps denying (was untested).
    d = evaluate_enforce(_input(boundary_id=""))
    assert d.decision == "deny"
    assert d.reason == "boundary_not_found"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_require_boundary.py -q`
Expected: FAIL — `TypeError: EnforceInput.__init__() got an unexpected keyword argument 'require_boundary'`.

- [ ] **Step 3: Add the `EnforceInput` field**

In `src/vinctor_core/models.py`, `EnforceInput` (frozen dataclass), add a trailing field:

```python
    require_boundary: bool = False
```

(Final field order: grant, action, resource, now, boundary_id=None, boundary_registry=None, require_boundary=False.)

- [ ] **Step 4: Add the `boundary_required` branch in `_resolve_boundary`**

In `src/vinctor_core/enforce.py`, change the absent branch (currently `if boundary_id is None: return None`):

```python
    boundary_id = enforce_input.boundary_id
    if boundary_id is None:
        if enforce_input.require_boundary:
            return _deny(
                enforce_input,
                "boundary_required",
                attempted_scope(enforce_input.action, enforce_input.resource),
            )
        return None
```

(The unusable branches below — `boundary_not_found` / `boundary_wrong_workspace` / `boundary_inactive` — are only reached when `boundary_id` is non-None, so an empty `""` still hits `boundary_not_found`. Untouched.)

- [ ] **Step 5: Run the core test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_require_boundary.py -q`
Expected: PASS (4 tests).

- [ ] **Step 6: Full suite + ruff, then commit**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src/ tests/`

```bash
git add src/vinctor_core/models.py src/vinctor_core/enforce.py tests/test_require_boundary.py
git commit -m "feat(require-boundary): EnforceInput.require_boundary + boundary_required deny (core)"
```

---

### Task 3: thread the flag through the service enforce paths (the wiring + fail-open guard)

**Files:**
- Modify: `src/vinctor_service/v1_enforce.py` (`_evaluate_and_record` + both contracts)
- Modify: `src/vinctor_service/in_memory.py` + `src/vinctor_service/sqlite.py` (service methods pass the repo)
- Test: `tests/test_require_boundary.py` (add service-level flag-ON/OFF tests)

- [ ] **Step 1: Write the failing service tests (the wiring guard)**

Append to `tests/test_require_boundary.py`:

```python
from vinctor_core import BoundaryRegistrationInput, register_boundary
from vinctor_service import InMemoryV1Service, V1DelegatedEnforceRequest, V1EnforceRequest


def _svc() -> InMemoryV1Service:
    return InMemoryV1Service(grants=(_grant(),))


def _harden(svc: InMemoryV1Service) -> None:
    svc.agent_enforcement_settings_repository.set_require_boundary(
        workspace_id="ws", agent_id="a", require_boundary=True, now=NOW
    )


def test_direct_enforce_hardened_agent_denies_without_boundary() -> None:
    svc = _svc()
    _harden(svc)
    r = svc.enforce(
        V1EnforceRequest(workspace_id="ws", agent_id="a", grant_ref="grt",
                         action="write", resource="repo/x/y"),
        now=NOW,
    )
    assert r.status_code == 403
    assert r.decision == "deny"


def test_direct_enforce_unhardened_agent_permits_without_boundary() -> None:
    svc = _svc()  # no flag
    r = svc.enforce(
        V1EnforceRequest(workspace_id="ws", agent_id="a", grant_ref="grt",
                         action="write", resource="repo/x/y"),
        now=NOW,
    )
    assert r.decision == "permit"


def test_delegated_enforce_hardened_subject_denies_without_boundary() -> None:
    svc = _svc()
    _harden(svc)
    r = svc.delegated_enforce(
        V1DelegatedEnforceRequest(pep_id="pep", workspace_id="ws", agent_id="a",
                                  grant_ref="grt", action="write", resource="repo/x/y",
                                  pep_workspace_id="ws"),
        now=NOW,
    )
    assert r.status_code == 403
    assert r.decision == "deny"
```

NB: confirm the exact `V1EnforceRequest` / `V1DelegatedEnforceRequest` field names against `src/vinctor_service/models.py` (the delegated one needs `pep_workspace_id` set so trusted-ws resolves; mirror `tests/test_delegated_enforce_contract.py`). Adjust the constructors to match.

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_require_boundary.py -k hardened -q`
Expected: FAIL — the hardened-agent cases PERMIT (flag not yet consulted).

- [ ] **Step 3: Thread `require_boundary` into `_evaluate_and_record`**

In `src/vinctor_service/v1_enforce.py` `_evaluate_and_record`, add a param (next to `token_id`):

```python
    require_boundary: bool = False,
```

and pass it into the `EnforceInput(...)` it builds:

```python
            boundary_registry=boundary_registry,
            require_boundary=require_boundary,
        )
```

- [ ] **Step 4: Resolve + pass the flag in both contracts**

In `enforce_v1_contract` (direct): add the keyword param to the signature:

```python
    agent_enforcement_settings_repository: AgentEnforcementSettingsRepository | None = None,
```

and just before its `return _evaluate_and_record(...)` call, resolve the flag on the request's `(workspace_id, agent_id)` and pass it:

```python
    require_boundary = (
        agent_enforcement_settings_repository.get_require_boundary(
            workspace_id=request.workspace_id, agent_id=request.agent_id
        )
        if agent_enforcement_settings_repository is not None
        else False
    )
    return _evaluate_and_record(
        ...,  # existing args unchanged
        require_boundary=require_boundary,
    )
```

In `delegated_enforce_v1_contract`: add the same keyword param, and resolve the flag on the **trusted** workspace + the validated subject agent (`trusted_ws`, `request.agent_id`) just before its `_evaluate_and_record(...)` call (after the grant-ownership check), passing `require_boundary=require_boundary`. Add `AgentEnforcementSettingsRepository` to the imports (TYPE_CHECKING or runtime as the file already imports repositories).

- [ ] **Step 5: Pass the repo from both service methods**

In `src/vinctor_service/in_memory.py` (`enforce` ~line 355 and `delegated_enforce` ~line 369) and `src/vinctor_service/sqlite.py` (`enforce` ~1093, `delegated_enforce` ~1107): add to each contract call:

```python
            agent_enforcement_settings_repository=self.agent_enforcement_settings_repository,
```

- [ ] **Step 6: Run the service tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_require_boundary.py -q`
Expected: PASS (all, incl. the hardened direct + delegated denies and the unhardened permit).

- [ ] **Step 7: Full suite + ruff, then commit**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src/ tests/`

```bash
git add src/vinctor_service/v1_enforce.py src/vinctor_service/in_memory.py src/vinctor_service/sqlite.py tests/test_require_boundary.py
git commit -m "feat(require-boundary): resolve + enforce the per-agent flag in both enforce paths"
```

---

### Task 4: operator CLI to toggle the flag

**Files:**
- Modify: `src/vinctor_service/cli.py` (subparser + dispatch + handler)
- Test: `tests/test_cli.py` (set/show round-trip)

- [ ] **Step 1: Write the failing CLI test**

Add to `tests/test_cli.py` (mirror the `operator bounds` direct-DB tests — `_run` + `--db`/`--workspace-id`):

```python
def test_vinctor_cli_operator_require_boundary_enable_show(tmp_path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]
    enabled = _run([*common, "operator", "require-boundary", "enable", "agent_runner"])
    shown = _run([*common, "operator", "require-boundary", "show", "agent_runner"])
    disabled = _run([*common, "operator", "require-boundary", "disable", "agent_runner"])
    shown_after = _run([*common, "operator", "require-boundary", "show", "agent_runner"])

    assert enabled["require_boundary"] is True
    assert shown["require_boundary"] is True
    assert disabled["require_boundary"] is False
    assert shown_after["require_boundary"] is False
```

(Confirm `_run` returns parsed JSON and that `--db`/`--workspace-id` are global args, per the existing `operator bounds` tests in this file.)

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_cli.py -k require_boundary -q`
Expected: FAIL — argparse error (`require-boundary` unknown).

- [ ] **Step 3: Register the subparser**

In `src/vinctor_service/cli.py` `_add_operator_commands`, after the `bounds` block (~line 236):

```python
    require_boundary = resources.add_parser("require-boundary")
    rb_commands = require_boundary.add_subparsers(dest="require_boundary_command", required=True)
    rb_enable = rb_commands.add_parser("enable")
    rb_enable.add_argument("target_agent_id", nargs="?")
    rb_disable = rb_commands.add_parser("disable")
    rb_disable.add_argument("target_agent_id", nargs="?")
    rb_show = rb_commands.add_parser("show")
    rb_show.add_argument("target_agent_id", nargs="?")
```

- [ ] **Step 4: Dispatch + handler**

In `_operator` (the resource dispatch, ~line 448 where `if resource == "bounds":`), add:

```python
    if resource == "require-boundary":
        _operator_require_boundary(args, stdout=stdout)
        return
```

Add the handler (mirror `_operator_bounds`):

```python
def _operator_require_boundary(args: argparse.Namespace, *, stdout: TextIO) -> None:
    service = _sqlite_service(args.db)
    agent_id = args.target_agent_id or args.agent_id
    repo = service.agent_enforcement_settings_repository
    if args.require_boundary_command in ("enable", "disable"):
        value = args.require_boundary_command == "enable"
        repo.set_require_boundary(
            workspace_id=args.workspace_id, agent_id=agent_id,
            require_boundary=value, now=datetime.now(UTC),
        )
    else:  # show
        value = repo.get_require_boundary(workspace_id=args.workspace_id, agent_id=agent_id)
    body = {
        "workspace_id": args.workspace_id,
        "agent_id": agent_id,
        "require_boundary": value,
    }
    _emit(
        args, body,
        f"require_boundary workspace={args.workspace_id} agent={agent_id} value={value}",
        stdout=stdout,
    )
```

(`datetime`, `UTC`, `TextIO`, `_sqlite_service`, `_emit` are already imported/used by `_operator_bounds`.)

- [ ] **Step 5: Run the CLI test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_cli.py -k require_boundary -q`
Expected: PASS.

- [ ] **Step 6: Full suite + ruff, then commit**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src/ tests/`

```bash
git add src/vinctor_service/cli.py tests/test_cli.py
git commit -m "feat(require-boundary): operator require-boundary enable/disable/show CLI"
```

---

## Final verification + handoff

- [ ] Full suite green: `.venv/bin/python -m pytest -q` and `.venv/bin/ruff check src/ tests/`.
- [ ] Update ADR 0009 Status to note direction B is now implemented (per-agent), referencing this spec/plan. Commit.
- [ ] Push the branch and open a PR (do NOT merge — main human-merge-only):

```bash
git push -u origin feat/adr0009-require-boundary
gh pr create --base main --head feat/adr0009-require-boundary \
  --title "feat: ADR 0009-B per-agent require_boundary (opt-in mandatory boundary)" \
  --body "Implements the accepted ADR 0009 direction B ... (default off; only the truly-absent boundary case denies boundary_required when set; both enforce paths; CLI toggle). 🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

## Notes for the implementer
- **Do not** normalize empty/whitespace `boundary_id` to `None` — that would flip the default-off empty-header path from `boundary_not_found` deny to permit (fail-open). The flag only acts on the truly-absent `None` case.
- The flag-ON service tests (Task 3) are the wiring guard: if a service method forgets to pass the settings repo, those tests go from deny → permit and fail. Keep them on BOTH the direct and delegated paths.
- Repo doesn't enforce `ruff format`; only `ruff check`.
