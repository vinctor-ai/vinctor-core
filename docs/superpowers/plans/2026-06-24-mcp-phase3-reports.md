# L — MCP Phase 3 visibility slice: composite read-only reports (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Add the highest-value, ZERO-new-service-surface slice of MCP Phase 3
(Operational UX / Authorization Visibility): two composite **read-only** tools that
synthesize existing reads (the `explain_denial` pattern), giving operators one-call
authorization-state views.

1. **`vinctor_grant_report`** — given a `grant_ref`: the grant (lifecycle: status +
   expires_at) plus its audit timeline partitioned into **lifecycle** events
   (`grant_issued` / `grant_revoked`) and **usage** events (enforcement decisions:
   `action_permitted` / `action_denied` / `access_rejected` / …).
2. **`vinctor_boundary_report`** — given a `boundary_id`: the boundary plus a summary
   of its recent audit activity (permit/deny counts) and the recent events.

**Why this is the right slice (from recon):** the audit endpoint already filters by
`grant_ref` / `boundary_id` / `agent_id` / `event_type`, so grant/boundary/agent-
centric audit *views* already work via `list_audit_events`; `explain_denial`,
`get_boundary`, `get_grant`, `list_grants?status=` already ship. The only genuinely
NEW value with no new service surface is composing those into the two reports above.
**Deferred** (need NEW service surface — out of this slice): durable grant lifecycle
timestamps (`revoked_at`/`issued_at`), an authoritative boundary→grant join,
server-side audit aggregation / time-range filtering, and subject-token /
workspace-settings read endpoints.

**Design (locked):** compose the EXISTING sibling tool methods of
`VinctorReadOnlyTools` (`get_grant`, `get_boundary`, `list_audit_events`) — each
already allowlist-shaped — and add only structural keys + server-computed integer
counts. NO new `service_client` methods, NO new HTTP endpoints, NO write surface.
These are READ tools (registered unconditionally, like the other read tools — NOT
behind `write_enabled`). Leak-safety is inherited: every nested object is produced by
an already-shaping sibling method; the report adds only fixed string keys + ints.

**Invariants:** MCP stays an inspection interface (no policy engine, no runtime
gateway, no authority). Read-only; allowlist discipline preserved. Repo
`/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/mcp-phase3-reports`, main human-merge-only. Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: `vinctor_grant_report` + `vinctor_boundary_report`

**Files:** `src/vinctor_mcp_server/tools.py` (two methods on `VinctorReadOnlyTools`
+ two `register_read_only_tools` registrations); tests `tests/test_mcp_tools.py`
(+ the registered-tool-name assertion).

- [x] **Step 1 — read the existing `VinctorReadOnlyTools`** to confirm the sibling
  method names/signatures: `get_grant(grant_ref)`, `get_boundary(boundary_id)`,
  `list_audit_events(...)` with a `grant_ref` and a `boundary_id` keyword filter, and
  the registered read-tool-name list assertion in `tests/test_mcp_tools.py`.
- [x] **Step 2 — failing tests** (use the existing FakeClient/Fake read-tool harness;
  feed leak bait — `raw_key`/`key_hash`/`raw_tool_input` — into the mocked grant +
  audit events and assert NONE leak):
  - `grant_report("grt_x")` returns `{"grant": <shaped grant>, "lifecycle":
    [<grant_issued/grant_revoked events, shaped>], "usage": [<enforcement events,
    shaped>]}`; partition is by `event_type`; no raw/internal field appears (safe AND
    diagnostic mode); calls `get_grant` once and `list_audit_events(grant_ref=...)`.
  - `boundary_report("bnd_x")` returns `{"boundary": <shaped boundary>, "activity":
    {"permit": <int>, "deny": <int>}, "recent": [<shaped events>]}`; counts derive
    from the shaped events' `decision`; no leak; calls `get_boundary` once and
    `list_audit_events(boundary_id=...)`.
  - both tools are registered as READ tools (present even when `write_enabled=False`).
- [x] **Step 3 — run, expect FAIL.**
- [x] **Step 4 — implement** on `VinctorReadOnlyTools` (compose sibling methods; add a
  module-level `_GRANT_LIFECYCLE_EVENT_TYPES = frozenset({"grant_issued",
  "grant_revoked"})`):

```python
    def grant_report(self, grant_ref: str) -> dict[str, Any]:
        grant = self.get_grant(grant_ref)
        events = self.list_audit_events(grant_ref=grant_ref)
        lifecycle = [e for e in events if e.get("event_type") in _GRANT_LIFECYCLE_EVENT_TYPES]
        usage = [e for e in events if e.get("event_type") not in _GRANT_LIFECYCLE_EVENT_TYPES]
        return {"grant": grant, "lifecycle": lifecycle, "usage": usage}

    def boundary_report(self, boundary_id: str) -> dict[str, Any]:
        boundary = self.get_boundary(boundary_id)
        events = self.list_audit_events(boundary_id=boundary_id)
        permit = sum(1 for e in events if e.get("decision") == "permit")
        deny = sum(1 for e in events if e.get("decision") == "deny")
        return {"boundary": boundary, "activity": {"permit": permit, "deny": deny}, "recent": events}
```

  (Match the real sibling signatures — if `list_audit_events` requires/accepts a
  `limit`, pass the existing default; if `get_grant`/`get_boundary`/`list_audit_events`
  differ in name, adapt while preserving the compose-only, no-new-shaping intent.)

- [x] **Step 5 — register** both in `register_read_only_tools`:

```python
    mcp.tool(
        name="vinctor_grant_report",
        description=(
            "Inspect a grant's authorization state: returns the grant (status, "
            "expiry) plus its audit timeline partitioned into lifecycle "
            "(issued/revoked) and usage (enforcement decisions). Read-only; output "
            "is allowlist-shaped and omits raw keys, hashes, and service internals."
        ),
    )(tools.grant_report)
    mcp.tool(
        name="vinctor_boundary_report",
        description=(
            "Inspect a boundary's authorization activity: returns the boundary plus "
            "a permit/deny summary and recent audit events for it. Read-only; output "
            "is allowlist-shaped and omits raw keys, hashes, and service internals."
        ),
    )(tools.boundary_report)
```

- [x] **Step 6 — update the registered read-tool-name assertion** in
  `tests/test_mcp_tools.py` to include `vinctor_grant_report` + `vinctor_boundary_report`.
- [x] **Step 7 — run tests + full suite + ruff; commit** `feat(mcp): Phase 3 composite read-only grant/boundary reports`.

---

## Final
- [x] Full suite + `ruff check src/ tests/` green.
- [x] Update `docs/mcp-server.md` (list the two new read tools) + `docs/next-actions.md`
  (MCP Phase 3: composite reports shipped; the deferred items — durable grant
  timestamps, boundary→grant join, server-side audit aggregation/time-range,
  subject-token + workspace-settings read endpoints — remain, each needing NEW
  service surface). Fold into the PR.
- [ ] Push branch, open PR (no merge; controller auto-merges after a final
  adversarial review per the march agreement).

## Notes
- These are pure MCP-side synthesis tools (the `explain_denial` precedent). They add
  NO service surface and reuse `VinctorServiceClient` unchanged.
- Leak-safety: every nested object comes from an already-allowlisting sibling method;
  the reports add only fixed string keys + integer counts. Still assert no leak in
  tests (defense in depth), including diagnostic mode.
- MCP-posture guardrails (do NOT cross): no policy evaluation, no runtime gateway, no
  authority — these only read + summarize existing audited state.
