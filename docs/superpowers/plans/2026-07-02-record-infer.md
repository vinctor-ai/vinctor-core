# Record → Infer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Propose a minimal least-privilege scope set from an agent's observed audit
trace — deterministically, propose-only, never auto-applied.

**Architecture:** A pure algorithm in `vinctor_core.infer` turns observed
`(action, resource)` counts into `ScopeProposal`s (exact by default; opt-in
`generalize` collapses deep siblings under a terminal wildcard). A thin
`vinctor operator policy infer` command in `vinctor_service` reads `audit_events`,
aggregates, calls the core, and emits a reviewable YAML/JSON proposal. See
[ADR 0010](../../decisions/0010-infer-scope-proposals-from-audit.md).

**Tech Stack:** Python 3.11, stdlib + PyYAML (already used by `policy_files`),
pytest, ruff. Reuses `vinctor_core.scope`.

---

## File structure

- Create: `src/vinctor_core/infer.py` — `Observation`, `ScopeProposal`,
  `propose_scopes()`. Pure, deterministic, DB/HTTP-agnostic.
- Create: `tests/test_infer.py` — unit tests for the algorithm.
- Modify (Task 2, CLI slice): `src/vinctor_service/cli.py` — add the
  `operator policy infer` subparser + handler.
- Create (Task 2): `src/vinctor_service/policy_infer.py` — read audit events →
  `Observation`s → `propose_scopes` → policy-document dict for YAML/JSON emit.
- Create (Task 2): `tests/test_policy_infer.py` — integration test over an
  in-memory/SQLite audit store.

---

## Task 1 — Core inference algorithm (this slice)

**Files:**
- Create: `src/vinctor_core/infer.py`
- Test: `tests/test_infer.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_infer.py
from __future__ import annotations

from vinctor_core.infer import Observation, ScopeProposal, propose_scopes


def _scopes(proposals):
    return [p.scope for p in proposals]


def test_empty_observations_yield_no_proposals():
    assert propose_scopes([]) == ()


def test_single_pair_yields_one_exact_scope():
    out = propose_scopes([Observation("read", "repo/feature/readme", count=1, last_seen="2026-07-01T00:00:00+00:00")])
    assert out == (
        ScopeProposal(
            scope="read:repo/feature/readme",
            count=1,
            last_seen="2026-07-01T00:00:00+00:00",
            generalized=False,
            covers=("read:repo/feature/readme",),
        ),
    )


def test_duplicates_aggregate_count_and_latest_last_seen():
    out = propose_scopes([
        Observation("read", "repo/feature/a", count=2, last_seen="2026-07-01T00:00:00+00:00"),
        Observation("read", "repo/feature/a", count=3, last_seen="2026-07-02T00:00:00+00:00"),
    ])
    assert [(p.scope, p.count, p.last_seen) for p in out] == [
        ("read:repo/feature/a", 5, "2026-07-02T00:00:00+00:00"),
    ]


def test_invalid_action_or_resource_is_dropped():
    out = propose_scopes([
        Observation("frobnicate", "repo/feature/a"),   # bad action
        Observation("read", "singleseg"),               # bad resource (<2 segments)
        Observation("read", "repo/../secrets"),         # traversal → invalid
        Observation("read", "repo/feature/a"),          # valid, kept
    ])
    assert _scopes(out) == ["read:repo/feature/a"]


def test_exact_mode_never_emits_wildcards_even_with_siblings():
    out = propose_scopes([
        Observation("read", "repo/feature/a"),
        Observation("read", "repo/feature/b"),
    ])
    assert _scopes(out) == ["read:repo/feature/a", "read:repo/feature/b"]
    assert all(not p.generalized for p in out)


def test_generalize_collapses_deep_siblings():
    out = propose_scopes([
        Observation("read", "repo/feature/a", count=1, last_seen="2026-07-01T00:00:00+00:00"),
        Observation("read", "repo/feature/b", count=2, last_seen="2026-07-03T00:00:00+00:00"),
    ], generalize=True)
    assert out == (
        ScopeProposal(
            scope="read:repo/feature/*",
            count=3,
            last_seen="2026-07-03T00:00:00+00:00",
            generalized=True,
            covers=("read:repo/feature/a", "read:repo/feature/b"),
        ),
    )


def test_generalize_refuses_shallow_siblings_exfil_footgun():
    # parent "net" has only 1 segment → do NOT widen to send:net/* .
    out = propose_scopes([
        Observation("send", "net/internal"),
        Observation("send", "net/external"),
    ], generalize=True)
    assert _scopes(out) == ["send:net/external", "send:net/internal"]
    assert all(not p.generalized for p in out)


def test_generalize_leaves_singletons_exact():
    out = propose_scopes([Observation("read", "repo/feature/a")], generalize=True)
    assert _scopes(out) == ["read:repo/feature/a"]
    assert out[0].generalized is False


def test_output_is_sorted_by_scope_deterministically():
    out = propose_scopes([
        Observation("write", "repo/x/z"),
        Observation("read", "repo/x/a"),
    ])
    assert _scopes(out) == ["read:repo/x/a", "write:repo/x/z"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_infer.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'vinctor_core.infer'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/vinctor_core/infer.py
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from vinctor_core.scope import (
    attempted_scope,
    is_valid_grant_scope,
    is_valid_requested_action,
    is_valid_requested_resource,
)


@dataclass(frozen=True)
class Observation:
    action: str
    resource: str
    count: int = 1
    last_seen: str | None = None


@dataclass(frozen=True)
class ScopeProposal:
    scope: str
    count: int
    last_seen: str | None
    generalized: bool
    covers: tuple[str, ...]


def _latest(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)  # ISO-8601 strings sort chronologically


def propose_scopes(
    observations: Iterable[Observation],
    *,
    generalize: bool = False,
) -> tuple[ScopeProposal, ...]:
    # Aggregate valid (action, resource) observations.
    agg: dict[tuple[str, str], tuple[int, str | None]] = {}
    for obs in observations:
        if not is_valid_requested_action(obs.action):
            continue
        if not is_valid_requested_resource(obs.resource):
            continue
        key = (obs.action, obs.resource)
        count, last_seen = agg.get(key, (0, None))
        agg[key] = (count + obs.count, _latest(last_seen, obs.last_seen))

    if not generalize:
        proposals = [
            ScopeProposal(
                scope=attempted_scope(action, resource),
                count=count,
                last_seen=last_seen,
                generalized=False,
                covers=(attempted_scope(action, resource),),
            )
            for (action, resource), (count, last_seen) in agg.items()
        ]
        return tuple(sorted(proposals, key=lambda p: p.scope))

    # Group by (action, parent) for generalization.
    groups: dict[tuple[str, str], list[tuple[str, int, str | None]]] = defaultdict(list)
    for (action, resource), (count, last_seen) in agg.items():
        parent = resource.rsplit("/", 1)[0]
        groups[(action, parent)].append((resource, count, last_seen))

    proposals: list[ScopeProposal] = []
    for (action, parent), members in groups.items():
        wildcard = f"{action}:{parent}/*"
        deep_enough = len(parent.split("/")) >= 2
        if len(members) >= 2 and deep_enough and is_valid_grant_scope(wildcard):
            total = sum(c for _, c, _ in members)
            latest: str | None = None
            for _, _, ls in members:
                latest = _latest(latest, ls)
            covers = tuple(sorted(attempted_scope(action, r) for r, _, _ in members))
            proposals.append(
                ScopeProposal(
                    scope=wildcard,
                    count=total,
                    last_seen=latest,
                    generalized=True,
                    covers=covers,
                )
            )
        else:
            for resource, count, last_seen in members:
                scope = attempted_scope(action, resource)
                proposals.append(
                    ScopeProposal(
                        scope=scope,
                        count=count,
                        last_seen=last_seen,
                        generalized=False,
                        covers=(scope,),
                    )
                )

    return tuple(sorted(proposals, key=lambda p: p.scope))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_infer.py -q`
Expected: PASS (9 tests).

- [ ] **Step 5: Lint + commit**

Run: `.venv/bin/ruff check src/vinctor_core/infer.py tests/test_infer.py`
```bash
git add src/vinctor_core/infer.py tests/test_infer.py
git commit -m "feat(core): deterministic scope inference (record→infer core)"
```

---

## Task 2 — `vinctor operator policy infer` CLI  ✅ IMPLEMENTED 2026-07-02

Shipped: `vinctor_service.policy_infer.infer_policy_document(events, *, agent_id,
since=None, until=None, generalize=False, include_denied=False)` (pure over any
audit-event objects), the `operator policy infer` subparser + handler in `cli.py`,
and `policy_files.dump_policy_document`. Output: YAML proposal to stdout (default),
`--file` writes YAML, `-o json` emits JSON. `--include-denied` renders a separate
`candidates_from_denied` list (never merged into `scopes`). `apply: false` marks it
propose-only. Tests: `tests/test_policy_infer.py` (5, incl. CLI wiring). Full suite
green (597 passed, 1 skipped); ruff clean.

**Files:**
- Create: `src/vinctor_service/policy_infer.py`
- Modify: `src/vinctor_service/cli.py` (add subparser under `operator policy` +
  dispatch to a handler)
- Test: `tests/test_policy_infer.py`

**Behavior:** read `audit_events` for `--agent <id>` within `--since/--until`,
default `event_type = action_permitted`; build `Observation(action, resource,
count, last_seen)` by aggregating rows; call `propose_scopes(obs,
generalize=args.generalize)`; emit a policy-document dict (reuse the
`policy_files` YAML shape — a candidate grant scope set + issuable-bounds) to
stdout or `--file`, annotated per scope with `count`, `last_seen`, and (for
generalized scopes) `covers`. **Propose-only — never call apply.**

- [ ] **Step 1: Write the failing integration test**

```python
# tests/test_policy_infer.py — sketch; fill exact audit-store setup from
# tests/test_audit_list_filtered.py conventions when executing.
from vinctor_service.policy_infer import infer_policy_document

def test_infer_document_proposes_exact_scopes_from_permitted_events(seeded_audit_store):
    doc = infer_policy_document(
        store=seeded_audit_store, agent_id="agent-1",
        since="2026-07-01T00:00:00+00:00", until=None, generalize=False,
    )
    scopes = [e["scope"] for e in doc["proposed"]["scopes"]]
    assert scopes == ["read:repo/feature/readme"]
    assert doc["proposed"]["apply"] is False  # propose-only marker
```

- [ ] **Step 2–5:** run-fail → implement `policy_infer.infer_policy_document`
  (aggregate rows → `propose_scopes` → dict) + wire the CLI subparser/handler →
  run-pass → `ruff` → commit.

**Wiring notes (verified anchors):** the `operator policy` subparser is defined in
`cli.py` near L607 (`policy_apply`/`policy_export`); add a `policy_infer` sibling
with `--agent` (required), `--since`, `--until`, `--generalize` (store_true),
`--include-denied` (store_true), `--file`, and the global `-o/--output`. Read audit
via the same service path `operator audit list` uses (see the `audit` subparser at
L582 and its handler). Emit YAML with `yaml.safe_dump(..., sort_keys=False)` as in
`policy_files.write_policy_file`.

---

## Self-review

- **Spec coverage:** exact-default ✅ (Task 1), opt-in generalize with parent-depth
  guard ✅, count/last_seen annotations ✅, covers for widening ✅, propose-only ✅
  (Task 2 `apply: false`), CLI surface ✅ (Task 2), consumes existing audit + scope
  grammar ✅. `--include-denied` (candidates) is specified in the spec; Task 2 wires
  the flag but denied→candidate rendering is a small follow-up within Task 2.
- **Placeholders:** Task 1 is fully concrete (real test + impl). Task 2's test uses
  a `seeded_audit_store` fixture to be finalized against
  `tests/test_audit_list_filtered.py` when executing — flagged, not hidden.
- **Type consistency:** `Observation`/`ScopeProposal` field names match across ADR,
  tests, and impl; `propose_scopes(observations, *, generalize=False)` signature is
  identical in every reference.
