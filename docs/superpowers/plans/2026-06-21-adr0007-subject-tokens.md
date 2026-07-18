# ADR 0007 Model 2 — Grant-Bound Subject Tokens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the on-behalf-of subject on `/v1/enforce/delegated` by requiring a Vinctor-issued, grant-bound, audience-scoped, short-lived token (`vat_`), minted by an agent for one of its own grants and presented by the PEP.

**Architecture:** A new `subject_tokens` store (hash-only, mirroring the key store) + a mint endpoint (`POST /v1/tokens`, agent-key auth) + an additive optional `X-Subject-Token` header on the existing delegated path. When the header is present, the subject (agent_id/workspace_id/grant_ref) is proven from the token and must equal both the asserted body and the resolved grant; failures fail closed. The decision is audited `subject_token_verified=true` with the `token_id`. The legacy no-token path is unchanged.

**Tech Stack:** Python 3.11, stdlib `http.server`, sqlite3, dataclasses; pytest; `ruff check` (the repo does NOT enforce `ruff format`).

**Source of truth:** the approved design spec `docs/superpowers/specs/2026-06-21-adr0007-subject-token-identity-proof-design.md`.

**Conventions for every task:** run from repo root `/Users/taeheon/dev/agent-authority/vinctor-core`, use the venv (`.venv/bin/python -m pytest`, `.venv/bin/ruff check`), branch `feat/adr0007-subject-tokens` (already checked out). Commit after each task. Do NOT merge to main (human-merge-only). Reuse `keys._new_key`/`keys._hash_key` — never reimplement hashing. Two prefixes that must never collide: raw token `vat_`, public id `vtk_`.

---

### Task 1: SubjectToken record + repository + schema + service wiring

**Files:**
- Modify: `src/vinctor_service/models.py` (add `SubjectToken` dataclass after `AutoApprovalRule`)
- Modify: `src/vinctor_service/repositories.py` (add `SubjectTokenRepository` Protocol + `InMemorySubjectTokenRepository`)
- Modify: `src/vinctor_service/sqlite.py` (table + version-3 row + `SQLiteSubjectTokenRepository` + `_subject_token_from_row` + service field)
- Modify: `src/vinctor_service/in_memory.py` (service field)
- Modify: `src/vinctor_service/__init__.py` (exports)
- Test: `tests/test_subject_token_repository.py` (new)
- Modify (cross-cutting): `tests/test_cli.py` (schema-version assertions `[1,2]`→`[1,2,3]`)

- [ ] **Step 1: Write the failing repository test**

Create `tests/test_subject_token_repository.py`:

```python
import sqlite3
from datetime import UTC, datetime, timedelta

from vinctor_service import (
    InMemorySubjectTokenRepository,
    SQLiteSubjectTokenRepository,
    SubjectToken,
)
from vinctor_service.sqlite import init_sqlite_schema, get_sqlite_schema_versions

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _token(token_hash: str = "hash_main") -> SubjectToken:
    return SubjectToken(
        token_id="vtk_main",
        token_hash=token_hash,
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        audience="pep_git_host",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=300),
        created_by="agent_release",
    )


def test_in_memory_insert_and_get_by_hash() -> None:
    repo = InMemorySubjectTokenRepository()
    repo.insert(_token())
    assert repo.get_by_hash("hash_main") == _token()
    assert repo.get_by_hash("missing") is None


def test_sqlite_insert_and_get_by_hash_round_trip(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = SQLiteSubjectTokenRepository(conn)
    repo.insert(_token())
    assert repo.get_by_hash("hash_main") == _token()
    assert repo.get_by_hash("missing") is None


def test_sqlite_schema_records_version_3(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    assert get_sqlite_schema_versions(conn) == [1, 2, 3]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_subject_token_repository.py -q`
Expected: FAIL — `ImportError: cannot import name 'SubjectToken'`.

- [ ] **Step 3: Add the `SubjectToken` record**

In `src/vinctor_service/models.py`, after the `AutoApprovalRule` class:

```python
@dataclass(frozen=True)
class SubjectToken:
    token_id: str        # public id, prefix vtk_
    token_hash: str      # SHA-256 of the raw vat_ token; raw is never stored
    workspace_id: str
    agent_id: str
    grant_ref: str
    audience: str        # target pep_id
    issued_at: datetime
    expires_at: datetime
    created_by: str      # minting agent
```

(`datetime` and `dataclass` are already imported in this file.)

- [ ] **Step 4: Add the Protocol + in-memory twin**

In `src/vinctor_service/repositories.py`, add `SubjectToken` to the `from vinctor_service.models import (...)` line, then add (mirroring `GrantRequestRepository`/`InMemoryGrantRequestRepository`):

```python
class SubjectTokenRepository(Protocol):
    def insert(self, token: SubjectToken) -> None: ...

    def get_by_hash(self, token_hash: str) -> SubjectToken | None: ...


class InMemorySubjectTokenRepository:
    def __init__(self, tokens: tuple[SubjectToken, ...] = ()) -> None:
        tokens_by_hash: dict[str, SubjectToken] = {}
        for token in tokens:
            if token.token_hash in tokens_by_hash:
                raise ValueError(f"duplicate subject token_hash: {token.token_hash}")
            tokens_by_hash[token.token_hash] = token
        self._tokens_by_hash = tokens_by_hash

    def insert(self, token: SubjectToken) -> None:
        if token.token_hash in self._tokens_by_hash:
            raise ValueError(f"duplicate subject token_hash: {token.token_hash}")
        self._tokens_by_hash[token.token_hash] = token

    def get_by_hash(self, token_hash: str) -> SubjectToken | None:
        return self._tokens_by_hash.get(token_hash)
```

- [ ] **Step 5: Add the SQLite table + version-3 row + repo + row helper**

In `src/vinctor_service/sqlite.py`: add `SubjectToken` to the `from vinctor_service.models import (...)` block. Inside `init_sqlite_schema`'s `executescript` block (alongside the other `CREATE TABLE` statements), add:

```sql
CREATE TABLE IF NOT EXISTS subject_tokens (
    token_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    workspace_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    grant_ref TEXT NOT NULL,
    audience TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_subject_tokens_hash
ON subject_tokens(token_hash);
```

Then, immediately after the version-2 `INSERT OR IGNORE INTO schema_migrations` block and **before** the final `conn.commit()`, add (NB the table is `schema_migrations`, NOT `schema_versions`):

```python
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (3, datetime.now(UTC).isoformat()),
    )
```

Add the repository class (mirroring `SQLiteGrantRequestRepository`):

```python
class SQLiteSubjectTokenRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def insert(self, token: SubjectToken) -> None:
        if self.get_by_hash(token.token_hash) is not None:
            raise ValueError(f"duplicate subject token_hash: {token.token_hash}")
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO subject_tokens (
                    token_id, token_hash, workspace_id, agent_id, grant_ref,
                    audience, issued_at, expires_at, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token.token_id, token.token_hash, token.workspace_id,
                    token.agent_id, token.grant_ref, token.audience,
                    token.issued_at.isoformat(), token.expires_at.isoformat(),
                    token.created_by,
                ),
            )

    def get_by_hash(self, token_hash: str) -> SubjectToken | None:
        row = self._conn.execute(
            """
            SELECT token_id, token_hash, workspace_id, agent_id, grant_ref,
                   audience, issued_at, expires_at, created_by
            FROM subject_tokens
            WHERE token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        return _subject_token_from_row(row)
```

Add the row helper next to `_grant_request_from_row`:

```python
def _subject_token_from_row(row: sqlite3.Row | tuple | None) -> SubjectToken | None:
    if row is None:
        return None
    return SubjectToken(
        token_id=row[0],
        token_hash=row[1],
        workspace_id=row[2],
        agent_id=row[3],
        grant_ref=row[4],
        audience=row[5],
        issued_at=datetime.fromisoformat(row[6]),
        expires_at=datetime.fromisoformat(row[7]),
        created_by=row[8],
    )
```

- [ ] **Step 6: Wire the repo field onto both services**

In `src/vinctor_service/in_memory.py`: add `InMemorySubjectTokenRepository` to the `from vinctor_service.repositories import (...)` block, and in `__post_init__` (beside `self.grant_request_repository = ...`):

```python
        self.subject_token_repository = InMemorySubjectTokenRepository()
```

In `src/vinctor_service/sqlite.py` `SQLiteV1Service`: add the class-body field declaration (beside the other `field(init=False)` repos):

```python
    subject_token_repository: SQLiteSubjectTokenRepository = field(init=False)
```

and in `__post_init__` (after `self.auto_approval_rule_repository = ...`):

```python
        self.subject_token_repository = SQLiteSubjectTokenRepository(self.conn)
```

- [ ] **Step 7: Export the new symbols**

In `src/vinctor_service/__init__.py`: add `SubjectToken`, `SubjectTokenRepository`, `InMemorySubjectTokenRepository` to the `from vinctor_service.repositories import (...)` block (and `SubjectToken` may come from models via repositories' re-export — import it from where the other records are imported), add `SQLiteSubjectTokenRepository` to the `from vinctor_service.sqlite import (...)` block, and add all four names to `__all__` (alphabetized).

- [ ] **Step 8: Run the repository test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_subject_token_repository.py -q`
Expected: PASS (3 tests).

- [ ] **Step 9: Fix the cross-cutting schema-version assertions**

The version-3 row changes existing assertions. In `tests/test_cli.py`, update every `schema_versions` / `schema_version` assertion: `[1, 2]` → `[1, 2, 3]` and `"schema_version": 2` → `"schema_version": 3` (the recon flagged lines ~377, 447, 524, 561 — grep to find all: `grep -n "schema_version" tests/test_cli.py`).

Run: `.venv/bin/python -m pytest tests/test_cli.py -q`
Expected: PASS (the updated assertions now match version 3).

- [ ] **Step 10: Full suite + ruff, then commit**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src/ tests/`
Expected: all pass, ruff clean.

```bash
git add src/vinctor_service/models.py src/vinctor_service/repositories.py src/vinctor_service/sqlite.py src/vinctor_service/in_memory.py src/vinctor_service/__init__.py tests/test_subject_token_repository.py tests/test_cli.py
git commit -m "feat(tokens): add SubjectToken record + repository + schema v3"
```

---

### Task 2: Audit fields `subject_token_verified` / `token_id` + new constants

**Files:**
- Modify: `src/vinctor_core/models.py` (`AuditEvent` fields + `to_dict`)
- Modify: `src/vinctor_core/audit.py` (`AuditEventInput` + `build_audit_event` + constants)
- Modify: `src/vinctor_service/sqlite.py` (`_audit_event_from_json` round-trip read)
- Test: `tests/test_audit.py` (add)

- [ ] **Step 1: Write the failing audit test**

Add to `tests/test_audit.py` (mirror the existing `enforcing_principal` tests):

```python
def test_audit_event_subject_token_verified_defaults_absent_from_to_dict() -> None:
    from vinctor_core.audit import AuditEventInput, build_audit_event
    from tests.helpers_audit import permit_decision  # use the same DecisionResult factory the file already uses

    event = build_audit_event(AuditEventInput(decision=permit_decision()))
    assert event.subject_token_verified is False
    assert event.token_id is None
    assert "subject_token_verified" not in event.to_dict()
    assert "token_id" not in event.to_dict()


def test_audit_event_records_subject_token_verified_and_token_id() -> None:
    from vinctor_core.audit import AuditEventInput, build_audit_event
    from tests.helpers_audit import permit_decision

    event = build_audit_event(
        AuditEventInput(decision=permit_decision(), subject_token_verified=True, token_id="vtk_x")
    )
    assert event.subject_token_verified is True
    assert event.to_dict()["subject_token_verified"] is True
    assert event.to_dict()["token_id"] == "vtk_x"
```

NB: use whatever `DecisionResult` factory `tests/test_audit.py` already uses for its `enforcing_principal` tests (around lines 201-235) instead of `helpers_audit`; copy that exact construction. Run `grep -n "build_audit_event\|AuditEventInput\|DecisionResult" tests/test_audit.py` first and mirror it.

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_audit.py -k subject_token_verified -q`
Expected: FAIL — `TypeError: AuditEventInput.__init__() got an unexpected keyword argument 'subject_token_verified'`.

- [ ] **Step 3: Add the two `AuditEvent` fields + conditional emit**

In `src/vinctor_core/models.py`, append to the `AuditEvent` optional fields (after `last_seen_at` at line 140):

```python
    # ADR 0007 Model 2 identity-proof (set only on a proven delegated decision).
    subject_token_verified: bool = False
    token_id: str | None = None
```

In `to_dict`, before `return event` (line 170-171), add — note `subject_token_verified` guards on truthiness (default False must stay absent), `token_id` on `is not None`:

```python
        if self.subject_token_verified:
            event["subject_token_verified"] = True
        if self.token_id is not None:
            event["token_id"] = self.token_id
```

- [ ] **Step 4: Add the `AuditEventInput` params + forward them + constants**

In `src/vinctor_core/audit.py`, add to `AuditEventInput`:

```python
    subject_token_verified: bool = False
    token_id: str | None = None
```

In `build_audit_event`, add to the `AuditEvent(...)` construction (after `enforcing_principal=audit_input.enforcing_principal,`):

```python
        subject_token_verified=audit_input.subject_token_verified,
        token_id=audit_input.token_id,
```

Beside the existing `EVENT_*` / `REASON_*` module constants, add:

```python
EVENT_SUBJECT_TOKEN_MINTED = "subject_token_minted"
REASON_SUBJECT_TOKEN_INVALID = "subject_token_invalid"
```

- [ ] **Step 5: Add the SQLite round-trip read**

In `src/vinctor_service/sqlite.py` `_audit_event_from_json` (the tail, mirroring the `enforcing_principal=data.get(...)` line ~1179):

```python
        subject_token_verified=data.get("subject_token_verified", False),
        token_id=data.get("token_id"),
```

- [ ] **Step 6: Add the SQLite round-trip test**

Add to `tests/test_sqlite_v1_service.py` a test mirroring the `enforcing_principal` persistence test (~lines 248-275): write an `AuditEvent` with `subject_token_verified=True, token_id="vtk_x"` through the service's audit writer (or via a delegated permit once Task 5 lands — for now, write directly via `SQLiteAuditWriter`), fetch it back, and assert `persisted.subject_token_verified is True and persisted.token_id == "vtk_x"`. If writing directly is awkward this early, defer this specific test to Task 5's proven-path round-trip and note it here; the `_audit_event_from_json` change is still required now.

- [ ] **Step 7: Run tests + ruff, then commit**

Run: `.venv/bin/python -m pytest tests/test_audit.py -q && .venv/bin/python -m pytest -q && .venv/bin/ruff check src/ tests/`
Expected: PASS, ruff clean.

```bash
git add src/vinctor_core/models.py src/vinctor_core/audit.py src/vinctor_service/sqlite.py tests/test_audit.py tests/test_sqlite_v1_service.py
git commit -m "feat(audit): add subject_token_verified/token_id fields + subject-token constants"
```

---

### Task 3: Mint logic — `subject_tokens.py` contract + service methods

**Files:**
- Create: `src/vinctor_service/subject_tokens.py`
- Modify: `src/vinctor_service/in_memory.py` (`mint_subject_token` method)
- Modify: `src/vinctor_service/sqlite.py` (`mint_subject_token` method)
- Modify: `src/vinctor_service/__init__.py` (export `SubjectTokenMintResult`)
- Test: `tests/test_subject_token_mint.py` (new)

- [ ] **Step 1: Write the failing mint test**

Create `tests/test_subject_token_mint.py`:

```python
from datetime import UTC, datetime, timedelta

from vinctor_core.models import Grant
from vinctor_service import InMemoryV1Service

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _grant(*, agent_id="agent_release", status="active", expires_at=NOW + timedelta(hours=1)) -> Grant:
    return Grant(
        grant_id="grnt_main", grant_ref="grt_main", workspace_id="ws_main",
        agent_id=agent_id, scopes=("write:repo/feature/*",), status=status,
        expires_at=expires_at,
    )


def _svc(grant: Grant) -> InMemoryV1Service:
    return InMemoryV1Service(grants=(grant,))


def _mint(svc, **over):
    kwargs = dict(workspace_id="ws_main", agent_id="agent_release",
                  grant_ref="grt_main", audience="pep_git_host",
                  ttl_seconds=300, now=NOW)
    kwargs.update(over)
    return svc.mint_subject_token(**kwargs)


def test_mint_for_owned_valid_grant_returns_token() -> None:
    svc = _svc(_grant())
    result = _mint(svc)
    assert result.status == "minted"
    assert result.token.startswith("vat_")
    assert result.token_id.startswith("vtk_")
    assert result.expires_at == NOW + timedelta(seconds=300)
    # a subject_token_minted audit row is written, never the raw token
    assert [e.event_type for e in svc.audit_events] == ["subject_token_minted"]
    assert result.token not in str(svc.audit_events[0].to_dict())


def test_mint_for_other_agents_grant_is_forbidden() -> None:
    svc = _svc(_grant(agent_id="agent_other"))
    assert _mint(svc).status == "forbidden"


def test_mint_for_revoked_grant_is_forbidden() -> None:
    svc = _svc(_grant(status="revoked"))
    assert _mint(svc).status == "forbidden"


def test_mint_for_time_expired_but_status_active_grant_is_forbidden() -> None:
    svc = _svc(_grant(expires_at=NOW - timedelta(hours=1)))
    assert _mint(svc).status == "forbidden"


def test_mint_clamps_expiry_to_grant_expiry() -> None:
    svc = _svc(_grant(expires_at=NOW + timedelta(seconds=60)))
    assert _mint(svc, ttl_seconds=300).expires_at == NOW + timedelta(seconds=60)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_subject_token_mint.py -q`
Expected: FAIL — `AttributeError: 'InMemoryV1Service' object has no attribute 'mint_subject_token'`.

- [ ] **Step 3: Write the mint contract module**

Create `src/vinctor_service/subject_tokens.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from secrets import token_urlsafe

from vinctor_core.audit import EVENT_SUBJECT_TOKEN_MINTED, AuditWriter
from vinctor_core.models import AuditEvent, Grant
from vinctor_service.keys import _hash_key, _new_key
from vinctor_service.models import SubjectToken
from vinctor_service.repositories import GrantRepository, SubjectTokenRepository


@dataclass(frozen=True)
class SubjectTokenMintResult:
    status: str  # "minted" | "forbidden"
    token: str | None = None
    token_id: str | None = None
    expires_at: datetime | None = None


def _grant_is_valid(grant: Grant, now: datetime) -> bool:
    # Mirror evaluate_enforce's validity (vinctor_core/enforce.py): status is
    # never flipped to 'expired', so a status=='active' grant past expires_at is
    # still 'active' — we must check expires_at explicitly.
    if grant.status in {"revoked", "expired"} or grant.status != "active":
        return False
    if grant.expires_at is not None and grant.expires_at <= now:
        return False
    return True


def mint_subject_token(
    *,
    grant_repository: GrantRepository,
    subject_token_repository: SubjectTokenRepository,
    audit_writer: AuditWriter,
    workspace_id: str,
    agent_id: str,
    grant_ref: str,
    audience: str,
    ttl_seconds: int,
    now: datetime,
) -> SubjectTokenMintResult:
    grant = grant_repository.get_by_ref(grant_ref)
    # Hand-rolled ownership equality (NOT lookup_grant, which omits agent_id).
    if (
        grant is None
        or grant.agent_id != agent_id
        or grant.workspace_id != workspace_id
        or not _grant_is_valid(grant, now)
    ):
        return SubjectTokenMintResult(status="forbidden")

    expires_at = now + timedelta(seconds=ttl_seconds)
    if grant.expires_at is not None and grant.expires_at < expires_at:
        expires_at = grant.expires_at  # never outlive the grant

    raw_token = _new_key("vat_")
    token_id = _new_key("vtk_")
    token = SubjectToken(
        token_id=token_id,
        token_hash=_hash_key(raw_token),
        workspace_id=workspace_id,
        agent_id=agent_id,
        grant_ref=grant_ref,
        audience=audience,
        issued_at=now,
        expires_at=expires_at,
        created_by=agent_id,
    )
    subject_token_repository.insert(token)
    audit_writer.write(_subject_token_minted_event(token=token, now=now))
    return SubjectTokenMintResult(
        status="minted", token=raw_token, token_id=token_id, expires_at=expires_at
    )


def _subject_token_minted_event(*, token: SubjectToken, now: datetime) -> AuditEvent:
    return AuditEvent(
        event_id=f"evt_{token_urlsafe(16)}",
        event_type=EVENT_SUBJECT_TOKEN_MINTED,
        decision="permit",
        reason=EVENT_SUBJECT_TOKEN_MINTED,
        workspace_id=token.workspace_id,
        agent_id=token.agent_id,
        grant_id="",
        grant_ref=token.grant_ref,
        action="",
        resource="",
        scope_attempted="",
        scope_matched=None,
        boundary_id=None,
        runtime=None,
        boundary_type=None,
        created_at=now,
        token_id=token.token_id,
    )
```

(Verify `AuditWriter` is importable from `vinctor_core.audit`; if it lives elsewhere, `grep -rn "class AuditWriter\|AuditWriter =" src/vinctor_core` and import from there.)

- [ ] **Step 4: Add the service method to both services**

In `src/vinctor_service/in_memory.py` (add a method on `InMemoryV1Service`, mirroring how `create_grant_request` delegates to a free function):

```python
    def mint_subject_token(
        self, *, workspace_id, agent_id, grant_ref, audience, ttl_seconds, now
    ):
        from vinctor_service.subject_tokens import mint_subject_token

        return mint_subject_token(
            grant_repository=self.grant_repository,
            subject_token_repository=self.subject_token_repository,
            audit_writer=self.audit_writer,
            workspace_id=workspace_id, agent_id=agent_id, grant_ref=grant_ref,
            audience=audience, ttl_seconds=ttl_seconds, now=now,
        )
```

Add the identical method to `SQLiteV1Service` in `src/vinctor_service/sqlite.py` (it has the same `grant_repository`/`subject_token_repository`/`audit_writer` attributes). Use a top-of-file import rather than the inline import if that matches the file's style.

- [ ] **Step 5: Export `SubjectTokenMintResult`**

In `src/vinctor_service/__init__.py`, add `SubjectTokenMintResult` to the `from vinctor_service.subject_tokens import (...)` block (create the block) and to `__all__`.

- [ ] **Step 6: Run the mint test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_subject_token_mint.py -q`
Expected: PASS (5 tests).

- [ ] **Step 7: Full suite + ruff, then commit**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src/ tests/`

```bash
git add src/vinctor_service/subject_tokens.py src/vinctor_service/in_memory.py src/vinctor_service/sqlite.py src/vinctor_service/__init__.py tests/test_subject_token_mint.py
git commit -m "feat(tokens): mint_subject_token contract + service methods"
```

---

### Task 4: `POST /v1/tokens` HTTP endpoint + config

**Files:**
- Modify: `src/vinctor_service/service_config.py` (constants)
- Modify: `src/vinctor_service/v1_http.py` (`V1TokenService` Protocol, `handle_v1_tokens_http`, `_parse_tokens_body`)
- Modify: `src/vinctor_service/local_http.py` (router branch + `_handle_tokens_request`)
- Modify: `src/vinctor_service/__init__.py` (export `handle_v1_tokens_http`, `V1TokenService`)
- Test: `tests/test_v1_tokens_http_contract.py` (new)

- [ ] **Step 1: Add config constants**

In `src/vinctor_service/service_config.py`, beside `DEFAULT_SERVICE_DB_PATH`:

```python
DEFAULT_SUBJECT_TOKEN_TTL_SECONDS = 300
DEFAULT_SUBJECT_TOKEN_MAX_TTL_SECONDS = 3600
```

- [ ] **Step 2: Write the failing HTTP contract test**

Create `tests/test_v1_tokens_http_contract.py` (mirror `tests/test_v1_http_contract.py` harness):

```python
from datetime import UTC, datetime, timedelta

from vinctor_core.models import Grant
from vinctor_service import AgentIdentity, InMemoryV1Service, handle_v1_tokens_http

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _grant(agent_id="agent_release") -> Grant:
    return Grant(grant_id="grnt_main", grant_ref="grt_main", workspace_id="ws_main",
                 agent_id=agent_id, scopes=("write:repo/feature/*",), status="active",
                 expires_at=NOW + timedelta(hours=1))


def _identities():
    return {"agent_key_main": AgentIdentity(workspace_id="ws_main", agent_id="agent_release")}


def _call(svc, *, headers=None, body=None):
    return handle_v1_tokens_http(
        headers={"X-Agent-Key": "agent_key_main"} if headers is None else headers,
        body={"grant_ref": "grt_main", "audience": "pep_git_host", "ttl_seconds": 300} if body is None else body,
        agent_identities=_identities(), service=svc, now=NOW,
    )


def test_mint_returns_201_with_token() -> None:
    svc = InMemoryV1Service(grants=(_grant(),))
    r = _call(svc)
    assert r.status_code == 201
    assert r.body["token"].startswith("vat_")
    assert r.body["token_id"].startswith("vtk_")
    assert "expires_at" in r.body


def test_mint_requires_agent_key_and_records_auth_failure() -> None:
    svc = InMemoryV1Service(grants=(_grant(),))
    r = _call(svc, headers={})
    assert r.status_code == 401
    assert r.body["error"] == "authentication_required"
    assert [e.event_type for e in svc.audit_events] == ["auth_failed"]


def test_mint_rejects_non_positive_ttl_with_400() -> None:
    svc = InMemoryV1Service(grants=(_grant(),))
    r = _call(svc, body={"grant_ref": "grt_main", "audience": "pep_git_host", "ttl_seconds": 0})
    assert r.status_code == 400
    assert r.body["error"] == "invalid_request"


def test_mint_rejects_ttl_over_max_with_400() -> None:
    svc = InMemoryV1Service(grants=(_grant(),))
    r = _call(svc, body={"grant_ref": "grt_main", "audience": "pep_git_host", "ttl_seconds": 999_999})
    assert r.status_code == 400


def test_mint_other_agents_grant_is_403_no_leak() -> None:
    svc = InMemoryV1Service(grants=(_grant(agent_id="agent_other"),))
    r = _call(svc)
    assert r.status_code == 403
    assert r.body["error"] == "forbidden"
    assert "grt_main" not in str(r.body)
```

- [ ] **Step 3: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_v1_tokens_http_contract.py -q`
Expected: FAIL — `ImportError: cannot import name 'handle_v1_tokens_http'`.

- [ ] **Step 4: Implement the Protocol, body parser, and handler**

In `src/vinctor_service/v1_http.py` add (mirroring `handle_v1_delegated_enforce_http` auth idiom + `grant_request_http` numeric validation):

```python
from vinctor_service.service_config import (
    DEFAULT_SUBJECT_TOKEN_MAX_TTL_SECONDS,
    DEFAULT_SUBJECT_TOKEN_TTL_SECONDS,
)


class V1TokenService(Protocol):
    def mint_subject_token(
        self, *, workspace_id: str, agent_id: str, grant_ref: str,
        audience: str, ttl_seconds: int, now: datetime,
    ) -> object: ...

    def record_auth_failure(self, *, surface: str, boundary_id: str | None, now: datetime) -> None: ...


def _parse_tokens_body(body: object, *, max_ttl: int) -> dict | V1HttpResponse:
    if not isinstance(body, dict):
        return _error(400, "invalid_request", "request body must be a JSON object")
    extra = set(body) - {"grant_ref", "audience", "ttl_seconds"}
    if extra:
        return _error(400, "invalid_request", f"unexpected field: {sorted(extra)[0]}")
    for field_name in ("grant_ref", "audience"):
        value = body.get(field_name)
        if not isinstance(value, str) or value == "":
            return _error(400, "invalid_request", f"{field_name} must be a non-empty string")
    ttl = body.get("ttl_seconds", DEFAULT_SUBJECT_TOKEN_TTL_SECONDS)
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
        return _error(400, "invalid_request", "ttl_seconds must be a positive integer")
    if ttl > max_ttl:
        return _error(400, "invalid_request", f"ttl_seconds exceeds maximum {max_ttl}")
    return {"grant_ref": body["grant_ref"], "audience": body["audience"], "ttl_seconds": ttl}


def handle_v1_tokens_http(
    *,
    headers: Mapping[str, str],
    body: object,
    agent_identities: Mapping[str, AgentIdentity] | None = None,
    agent_identity_resolver: AgentIdentityResolver | None = None,
    service: V1TokenService,
    now: datetime,
    max_ttl: int = DEFAULT_SUBJECT_TOKEN_MAX_TTL_SECONDS,
) -> V1HttpResponse:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    agent_key = normalized_headers.get("x-agent-key")
    identity = None
    if agent_key is not None:
        if agent_identity_resolver is not None:
            identity = agent_identity_resolver(agent_key, now)
        else:
            identity = (agent_identities or {}).get(agent_key)
    if identity is None:
        service.record_auth_failure(surface="tokens", boundary_id=None, now=now)
        return _error(401, "authentication_required", "valid X-Agent-Key header is required")
    parsed = _parse_tokens_body(body, max_ttl=max_ttl)
    if isinstance(parsed, V1HttpResponse):
        return parsed
    result = service.mint_subject_token(
        workspace_id=identity.workspace_id, agent_id=identity.agent_id,
        grant_ref=parsed["grant_ref"], audience=parsed["audience"],
        ttl_seconds=parsed["ttl_seconds"], now=now,
    )
    if result.status != "minted":
        return _error(403, "forbidden", "subject token could not be issued")
    return V1HttpResponse(
        status_code=201,
        body={"token": result.token, "token_id": result.token_id,
              "expires_at": result.expires_at.isoformat()},
    )
```

(Match the exact names already in `v1_http.py`: `_error`, `V1HttpResponse`, `AgentIdentity`, `AgentIdentityResolver`, `Mapping`. If `AgentIdentityResolver` isn't imported here, copy the import used by the delegated handler.)

- [ ] **Step 5: Add the router branch**

In `src/vinctor_service/local_http.py` `_handle_request`, add before the `/v1/boundaries` branch:

```python
        if path == "/v1/tokens":
            _handle_tokens_request(handler, method)
            return
```

and the handler (mirror `_handle_delegated_enforce_request`, but auth is X-Agent-Key so pass `agent_identities`/`agent_identity_resolver`):

```python
    def _handle_tokens_request(handler, method):
        if method != "POST":
            _send_json(handler, V1HttpResponse(405, {"error": "method_not_allowed",
                       "reason": "POST is required for /v1/tokens"}))
            return
        parsed = _read_json_body(handler)
        if isinstance(parsed, V1HttpResponse):
            _send_json(handler, parsed)
            return
        response = handle_v1_tokens_http(
            headers=dict(handler.headers.items()), body=parsed,
            agent_identities=agent_keys, agent_identity_resolver=agent_identity_resolver,
            service=cast(V1TokenService, service), now=now(),
            max_ttl=int(os.environ.get(
                "VINCTOR_SUBJECT_TOKEN_MAX_TTL_SECONDS",
                DEFAULT_SUBJECT_TOKEN_MAX_TTL_SECONDS,
            )),
        )
        _send_json(handler, response)
```

(Use the exact local names already in scope in this factory — `agent_keys`/`agent_identities`, `agent_identity_resolver`, `service`, `now`, `_send_json`, `_read_json_body`, `cast`. Add `handle_v1_tokens_http, V1TokenService` to the `from vinctor_service.v1_http import (...)` import, `import os` if not present, and `from vinctor_service.service_config import DEFAULT_SUBJECT_TOKEN_MAX_TTL_SECONDS`. This reads the `VINCTOR_SUBJECT_TOKEN_MAX_TTL_SECONDS` ceiling per the spec; it may be hoisted to factory-construction time if preferred. Add a contract test that a too-large `ttl_seconds` is rejected when the env var lowers the ceiling.)

- [ ] **Step 6: Export + run the test**

Add `handle_v1_tokens_http`, `V1TokenService` to `src/vinctor_service/__init__.py` and `__all__`.

Run: `.venv/bin/python -m pytest tests/test_v1_tokens_http_contract.py -q`
Expected: PASS (5 tests).

- [ ] **Step 7: Full suite + ruff, then commit**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src/ tests/`

```bash
git add src/vinctor_service/service_config.py src/vinctor_service/v1_http.py src/vinctor_service/local_http.py src/vinctor_service/__init__.py tests/test_v1_tokens_http_contract.py
git commit -m "feat(tokens): POST /v1/tokens mint endpoint"
```

---

### Task 5: Delegated proven path — contract

**Files:**
- Modify: `src/vinctor_service/models.py` (`V1DelegatedEnforceRequest.subject_token`)
- Modify: `src/vinctor_service/v1_enforce.py` (proven branch + `_evaluate_and_record` params)
- Modify: `src/vinctor_service/in_memory.py` + `src/vinctor_service/sqlite.py` (`delegated_enforce` passes `subject_token_repository`)
- Test: `tests/test_delegated_enforce_contract.py` (add)

- [ ] **Step 1: Write the failing proven-path unit tests**

Add to `tests/test_delegated_enforce_contract.py` (reuse its `request()`/`repository()`/`grant()` helpers; add a subject-token repo + a minted token). Cover the invariant matrix:

```python
from datetime import timedelta

from vinctor_core.audit import REASON_SUBJECT_TOKEN_INVALID
from vinctor_service.keys import _hash_key, _new_key
from vinctor_service.models import SubjectToken
from vinctor_service.repositories import InMemorySubjectTokenRepository


def _raw_and_repo(*, audience="pep_git_host", workspace_id="ws_main",
                  agent_id="agent_release", grant_ref="grt_main",
                  expires_at=None):
    raw = _new_key("vat_")
    token = SubjectToken(
        token_id=_new_key("vtk_"), token_hash=_hash_key(raw),
        workspace_id=workspace_id, agent_id=agent_id, grant_ref=grant_ref,
        audience=audience, issued_at=NOW,
        expires_at=expires_at or (NOW + timedelta(seconds=300)),
        created_by=agent_id,
    )
    repo = InMemorySubjectTokenRepository((token,))
    return raw, token, repo


def test_proven_path_permits_and_marks_subject_token_verified() -> None:
    audit = InMemoryAuditWriter()
    raw, token, repo = _raw_and_repo()
    response = delegated_enforce_v1_contract(
        request(subject_token=raw), grant_repository=repository(grant()),
        now=NOW, audit_writer=audit, subject_token_repository=repo,
    )
    assert response.decision == "permit"
    assert audit.events[0].subject_token_verified is True
    assert audit.events[0].token_id == token.token_id


def test_expired_token_fails_closed() -> None:
    audit = InMemoryAuditWriter()
    raw, _, repo = _raw_and_repo(expires_at=NOW - timedelta(seconds=1))
    response = delegated_enforce_v1_contract(
        request(subject_token=raw), grant_repository=repository(grant()),
        now=NOW, audit_writer=audit, subject_token_repository=repo,
    )
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert audit.events[0].reason_code == REASON_SUBJECT_TOKEN_INVALID


def test_audience_mismatch_fails_closed() -> None:
    audit = InMemoryAuditWriter()
    raw, _, repo = _raw_and_repo(audience="pep_other_host")
    response = delegated_enforce_v1_contract(
        request(subject_token=raw), grant_repository=repository(grant()),
        now=NOW, audit_writer=audit, subject_token_repository=repo,
    )
    assert response.status_code == 403


def test_token_subject_mismatch_with_body_fails_closed() -> None:
    audit = InMemoryAuditWriter()
    raw, _, repo = _raw_and_repo(agent_id="agent_other")  # token says agent_other, body says agent_release
    response = delegated_enforce_v1_contract(
        request(subject_token=raw), grant_repository=repository(grant()),
        now=NOW, audit_writer=audit, subject_token_repository=repo,
    )
    assert response.status_code == 403


def test_token_store_error_fails_closed_not_503() -> None:
    class Boom:
        def get_by_hash(self, token_hash):
            raise RuntimeError("store down")
    audit = InMemoryAuditWriter()
    raw, _, _ = _raw_and_repo()
    response = delegated_enforce_v1_contract(
        request(subject_token=raw), grant_repository=repository(grant()),
        now=NOW, audit_writer=audit, subject_token_repository=Boom(),
    )
    assert response.status_code == 403  # NOT 503, NOT a permit


def test_no_token_legacy_path_unchanged() -> None:
    audit = InMemoryAuditWriter()
    response = delegated_enforce_v1_contract(
        request(), grant_repository=repository(grant()),
        now=NOW, audit_writer=audit, subject_token_repository=InMemorySubjectTokenRepository(),
    )
    assert response.decision == "permit"
    assert audit.events[0].subject_token_verified is False
    assert "subject_token_verified" not in audit.events[0].to_dict()
```

NB: add a `subject_token: str | None = None` param to the test's local `request(...)` helper so these compile; mirror how it already sets `pep_workspace_id`. Confirm `response.error`/`response.status_code` attribute names against the existing tests in this file and adjust.

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_delegated_enforce_contract.py -k "proven or token or legacy" -q`
Expected: FAIL — `TypeError: delegated_enforce_v1_contract() got an unexpected keyword argument 'subject_token_repository'`.

- [ ] **Step 3: Add the request field**

In `src/vinctor_service/models.py` `V1DelegatedEnforceRequest` (frozen dataclass), add a NEW TRAILING optional field after `pep_workspace_id`:

```python
    subject_token: str | None = None
```

- [ ] **Step 4: Implement the proven branch in `delegated_enforce_v1_contract`**

In `src/vinctor_service/v1_enforce.py`:
- Add the keyword param `subject_token_repository: SubjectTokenRepository | None = None` to `delegated_enforce_v1_contract`.
- Add `subject_token_verified: bool = False` and `token_id: str | None = None` params to `_evaluate_and_record`, and forward them into its `AuditEventInput(...)`.
- After the existing grant resolution + the grant-ownership equality (line ~155), but on the token-present path, insert the proven checks **before** calling `_evaluate_and_record`, computing `proven` flags to pass through. Implementation:

```python
    # ADR 0007 Model 2: proven-identity path. The token (if present) must agree
    # with the asserted body AND the resolved grant; any failure fails closed.
    subject_token_verified = False
    proven_token_id = None
    if request.subject_token is not None:
        try:
            token = (
                subject_token_repository.get_by_hash(_hash_key(request.subject_token))
                if subject_token_repository is not None
                else None
            )
        except Exception:
            token = None
            token_lookup_failed = True
        else:
            token_lookup_failed = False
        if token is None or token_lookup_failed:
            _record_rejection(
                audit_writer, reason_code=REASON_SUBJECT_TOKEN_INVALID,
                workspace_id=trusted_ws, agent_id=request.agent_id,
                action=request.action, resource=request.resource,
                boundary_id=request.boundary_id, now=now,
                enforcing_principal=request.pep_id,
            )
            return _pre_audit_error(403, "forbidden", "subject token is not valid")
        # audience (workspace,pep_id pair) + identity tuple + expiry
        if (
            token.expires_at <= now
            or token.audience != request.pep_id
            or token.workspace_id != trusted_ws
            or token.agent_id != request.agent_id
            or token.workspace_id != request.workspace_id
            or token.grant_ref != request.grant_ref
            or token.agent_id != grant.agent_id
            or token.workspace_id != grant.workspace_id
            or token.grant_ref != grant.grant_ref
        ):
            _record_rejection(
                audit_writer, reason_code=REASON_SUBJECT_TOKEN_INVALID,
                workspace_id=trusted_ws, agent_id=request.agent_id,
                action=request.action, resource=request.resource,
                boundary_id=request.boundary_id, now=now,
                enforcing_principal=request.pep_id,
            )
            return _pre_audit_error(403, "forbidden", "subject token is not valid")
        subject_token_verified = True
        proven_token_id = token.token_id
```

Then pass `subject_token_verified=subject_token_verified, token_id=proven_token_id` into the existing `_evaluate_and_record(...)` call on the delegated path. Add the imports `from vinctor_core.audit import REASON_SUBJECT_TOKEN_INVALID` and `from vinctor_service.keys import _hash_key` and `from vinctor_service.repositories import SubjectTokenRepository` (TYPE_CHECKING is fine for the last).

IMPORTANT (fail-closed): this token block must run AFTER the grant is resolved (so `grant` exists) and must NOT be reached through the existing `except Exception -> 503` grant branch. The token lookup has its own `try/except` returning 403 — never 503.

- [ ] **Step 5: Thread the repo through the service `delegated_enforce`**

In `src/vinctor_service/in_memory.py` and `src/vinctor_service/sqlite.py`, the `delegated_enforce` methods call `delegated_enforce_v1_contract(...)` — add `subject_token_repository=self.subject_token_repository` to both call sites. (`request.subject_token` already rides on the request object.)

- [ ] **Step 6: Run the proven-path tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_delegated_enforce_contract.py -q`
Expected: PASS (existing + new).

- [ ] **Step 7: Full suite + ruff, then commit**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src/ tests/`

```bash
git add src/vinctor_service/models.py src/vinctor_service/v1_enforce.py src/vinctor_service/in_memory.py src/vinctor_service/sqlite.py tests/test_delegated_enforce_contract.py
git commit -m "feat(tokens): proven-identity delegated enforce path (contract)"
```

---

### Task 6: Delegated proven path — HTTP threading + SQLite round-trip

**Files:**
- Modify: `src/vinctor_service/v1_http.py` (`handle_v1_delegated_enforce_http` reads `X-Subject-Token`)
- Test: `tests/test_delegated_enforce_http_contract.py` (add)
- Test: `tests/test_sqlite_v1_service.py` (proven round-trip, if deferred from Task 2)

- [ ] **Step 1: Write the failing HTTP proven-path tests**

Add to `tests/test_delegated_enforce_http_contract.py` (reuse its `grant()`/`service()`/`pep_identities()`/`body()`/`call()` helpers). Mint a token on the service first, then present it:

```python
def _mint_raw(svc, *, audience="pep_git_host"):
    result = svc.mint_subject_token(
        workspace_id="ws_main", agent_id="agent_release", grant_ref="grt_main",
        audience=audience, ttl_seconds=300, now=NOW,
    )
    return result.token, result.token_id


def test_http_proven_permit_records_subject_token_verified() -> None:
    svc = service()
    raw, token_id = _mint_raw(svc)
    response = call(svc, headers={"X-PEP-Key": "pep_key_main", "X-Subject-Token": raw})
    assert response.status_code == 200
    proven = next(e for e in svc.audit_events if e.event_type != "subject_token_minted")
    assert proven.subject_token_verified is True
    assert proven.token_id == token_id
    assert raw not in str(response.body)


def test_http_audience_mismatch_fails_closed() -> None:
    svc = service()
    raw, _ = _mint_raw(svc, audience="pep_other_host")
    response = call(svc, headers={"X-PEP-Key": "pep_key_main", "X-Subject-Token": raw})
    assert response.status_code == 403


def test_http_missing_pep_key_with_token_still_401_first() -> None:
    svc = service()
    raw, _ = _mint_raw(svc)
    response = call(svc, headers={"X-Subject-Token": raw})  # no X-PEP-Key
    assert response.status_code == 401


def test_http_no_token_is_unproven_regression() -> None:
    svc = service()
    response = call(svc, headers={"X-PEP-Key": "pep_key_main"})
    assert response.status_code == 200
    assert svc.audit_events[0].subject_token_verified is False
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_delegated_enforce_http_contract.py -k "proven or audience or token or regression" -q`
Expected: FAIL — proven assertions fail because `X-Subject-Token` is not read yet (`subject_token_verified` is False).

- [ ] **Step 3: Read the header and thread it**

In `src/vinctor_service/v1_http.py` `handle_v1_delegated_enforce_http`, add to the `V1DelegatedEnforceRequest(...)` construction:

```python
        subject_token=normalized_headers.get("x-subject-token"),
```

(The 401-before-token-logic ordering is already correct: the PEP-key/`record_auth_failure` guard runs before the request is built. Do not move it.)

- [ ] **Step 4: Run the HTTP proven-path tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_delegated_enforce_http_contract.py -q`
Expected: PASS.

- [ ] **Step 5: SQLite proven round-trip test**

Add to `tests/test_sqlite_v1_service.py` (mirror the `enforcing_principal` round-trip ~248-275): build a `SQLiteV1Service`, mint a token, run a delegated proven enforce, fetch the decision audit via `service.get_audit_event(response.audit_event_id)`, assert `persisted.subject_token_verified is True and persisted.token_id == <vtk_ id>`.

Run: `.venv/bin/python -m pytest tests/test_sqlite_v1_service.py -q`
Expected: PASS.

- [ ] **Step 6: Full suite + ruff, then commit**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src/ tests/`

```bash
git add src/vinctor_service/v1_http.py tests/test_delegated_enforce_http_contract.py tests/test_sqlite_v1_service.py
git commit -m "feat(tokens): thread X-Subject-Token through delegated enforce HTTP"
```

---

### Task 7: CLI `agent token mint` + `local start` PEP wiring

**Files:**
- Modify: `src/vinctor_service/cli.py` (subparser + handler branch)
- Modify: `src/vinctor_service/local_launcher.py` (wire `pep_identity_resolver`)
- Test: `tests/test_cli.py` (mint e2e)

- [ ] **Step 1: Write the failing CLI e2e test**

Add to `tests/test_cli.py` (reuse `_start_service`/`_common_args`/`_run`/`_stop_service`):

```python
def test_vinctor_cli_agent_token_mint(tmp_path) -> None:
    handle = _start_service(tmp_path, scopes=("write:repo/feature/*",))
    try:
        common = _common_args(handle, json_output=True)
        result = _run([*common, "agent", "token", "mint",
                       "--grant-ref", handle.grant_ref, "--audience", "pep_git_host"])
        assert result["token"].startswith("vat_")
        assert result["token_id"].startswith("vtk_")
        assert "expires_at" in result
    finally:
        _stop_service(handle)
```

(Confirm `handle.grant_ref` is the bootstrap grant exposed by `LocalServiceHandle`; if the attribute differs, use the value `_common_args` already passes for `--grant-ref`.)

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_cli.py -k token_mint -q`
Expected: FAIL — argparse error / unknown command `token`.

- [ ] **Step 3: Register the subparser**

In `src/vinctor_service/cli.py` `_add_agent_commands`, after the `enforce` subparser:

```python
    token = commands.add_parser("token")
    token_commands = token.add_subparsers(dest="token_command", required=True)
    mint = token_commands.add_parser("mint")
    mint.add_argument("--grant-ref", dest="token_grant_ref", required=True)
    mint.add_argument("--audience", required=True)
    mint.add_argument("--ttl")
```

(`dest="token_grant_ref"` avoids clobbering the global `--grant-ref`.)

- [ ] **Step 4: Implement the handler branch**

In `_agent(...)`, before the final `raise CliError("unknown agent command")`:

```python
    if args.agent_command == "token" and args.token_command == "mint":
        status, body = _request_json(
            args.endpoint, "POST", "/v1/tokens",
            headers={"X-Agent-Key": _required(args.agent_key, "agent key")},
            body={
                "grant_ref": _required(args.token_grant_ref, "grant ref"),
                "audience": _required(args.audience, "audience"),
                "ttl_seconds": _parse_duration_seconds(args.ttl) if args.ttl
                               else DEFAULT_SUBJECT_TOKEN_TTL_SECONDS,
            },
        )
        _raise_for_status(status, body)
        text = "\n".join([
            f"minted subject token token_id={body['token_id']} expires_at={body['expires_at']}",
            f"token={body['token']}",
            "# Store this raw token now; it cannot be recovered from SQLite.",
        ])
        _emit(args, body, text, stdout=stdout)
        return
```

Add `from vinctor_service.service_config import DEFAULT_SUBJECT_TOKEN_TTL_SECONDS` to cli.py imports.

- [ ] **Step 5: Wire the PEP resolver into `local start`**

In `src/vinctor_service/local_launcher.py` `prepare_local_service`, in the `create_v1_http_server(...)` call, add beside the existing `agent_identity_resolver=`/`workspace_identity_resolver=` kwargs:

```python
        pep_identity_resolver=lambda raw_key, used_at: key_repository.resolve_pep_identity(
            raw_key, now=used_at
        ),
```

(Copied verbatim from `service_runtime.py`; `key_repository` is the same local name. This makes the proven delegated path reachable via `local start`.)

- [ ] **Step 6: Run the CLI test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_cli.py -k token_mint -q`
Expected: PASS.

- [ ] **Step 7: Full suite + ruff, then commit**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src/ tests/`
Expected: all green.

```bash
git add src/vinctor_service/cli.py src/vinctor_service/local_launcher.py tests/test_cli.py
git commit -m "feat(tokens): agent token mint CLI + local-start PEP wiring"
```

---

## Final verification

- [ ] Run the whole suite once more: `.venv/bin/python -m pytest -q` (all pass) and `.venv/bin/ruff check src/ tests/` (clean).
- [ ] Push the branch and open a PR (do NOT merge — main is human-merge-only):

```bash
git push -u origin feat/adr0007-subject-tokens
gh pr create --base main --head feat/adr0007-subject-tokens \
  --title "feat: ADR 0007 Model 2 grant-bound subject tokens (identity proof)" \
  --body "Implements the approved spec docs/superpowers/specs/2026-06-21-adr0007-subject-token-identity-proof-design.md. ..."
```

- [ ] Update ADR 0007 Status to note Model 2 identity-proof is implemented (separate small doc edit/PR, or include in this PR's description for the founder to fold into the ADR on merge).

## Notes for the implementer

- **Fail-closed is the load-bearing invariant:** the subject-token lookup must return 403 on not-found AND on any exception — never 503, never fall through to the legacy asserted path. This is the opposite of the existing grant-lookup 503 behavior; do not copy that branch.
- **`status=='active'` ≠ valid:** the codebase never flips grant status to `expired`; mint must check `expires_at > now` explicitly (Task 3 has a dedicated test).
- **Two prefixes, never confused:** raw `vat_` (secret, returned once), id `vtk_` (public, audited). The raw token must never appear in any audit row or response except the one-time mint body.
- **Do not overload `reason_code`** for proven decisions — `subject_token_verified`/`token_id` are dedicated fields; `reason_code=subject_token_invalid` is only on the rejection path.
- The repo does NOT enforce `ruff format`; only run `ruff check`. Only format files your edits dirtied that were clean on main.
