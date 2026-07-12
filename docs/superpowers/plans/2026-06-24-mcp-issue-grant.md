# H — MCP grants.issue write tool (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Complete the MCP Phase 2 write set with the opt-in operator tool
`vinctor_issue_grant`, proxying the existing `POST /v1/grants` issue endpoint
(workspace-key-authed, service-bounded). Mirrors the shipped `vinctor_revoke_grant`
exactly. MCP-only; the HTTP endpoint already exists.

**Design (locked):** opt-in under `VINCTOR_MCP_WRITE` (default off → unchanged);
reuse the workspace key; proxy `POST /v1/grants`; allowlist-shape the response with
the existing `_grant_fields()` + `audit_event_id`. The **service** enforces
issuable-scope bounds (403 `scope_outside_issuable_bounds` / `ttl_exceeds_issuable_max`
/ `issuable_bounds_not_found`) — the MCP mints nothing and adds no bound. No schema
change, no config change (the write-mode gate already covers it).

Repo `/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/mcp-issue-grant`, main human-merge-only. Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: `vinctor_issue_grant` (client + tool + registration)

**Files:** `src/vinctor_mcp_server/service_client.py`, `src/vinctor_mcp_server/tools.py`;
tests `tests/test_mcp_service_client.py` + `tests/test_mcp_tools.py`.

- [ ] **Step 1 — failing tests:**
  - `VinctorServiceClient.issue_grant(agent_id="aid", scopes=["read:x/*"],
    ttl_seconds=3600)` → `POST /v1/grants` with `X-Workspace-Key` and a JSON body
    of EXACTLY `{"agent_id": "aid", "scopes": ["read:x/*"], "ttl_seconds": 3600}`
    (no `workspace_id` — the service derives it from the key; no `ttl` alias).
  - `VinctorWriteTools.issue_grant("aid", ["read:x/*"], 3600)` → calls the client
    and returns an allowlist-shaped result (grant fields + `audit_event_id`), NO
    raw key/hash/internal even if the mocked 201 body contains them; `scopes`
    appears only in diagnostic mode.
  - with `write_enabled=True`, `vinctor_issue_grant` is registered; with
    `write_enabled=False` (default) it is NOT registered.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — client** (mirror `revoke_grant`; this one sends a body):

```python
    def issue_grant(
        self, *, agent_id: str, scopes: list[str], ttl_seconds: int
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            "/v1/grants",
            body={"agent_id": agent_id, "scopes": list(scopes), "ttl_seconds": ttl_seconds},
        )
```

- [ ] **Step 4 — Protocol + tool:** add `issue_grant(self, *, agent_id: str,
  scopes: list[str], ttl_seconds: int) -> dict[str, Any]` to the `WriteVinctorClient`
  Protocol; add to `VinctorWriteTools` (note: MCP tool methods use positional params
  so the LLM supplies them — drop the `*`, mirroring the read tools):

```python
    def issue_grant(
        self, agent_id: str, scopes: list[str], ttl_seconds: int
    ) -> dict[str, Any]:
        body = self._client.issue_grant(
            agent_id=agent_id, scopes=scopes, ttl_seconds=ttl_seconds
        )
        return {
            **allowlist_object(body, self._grant_fields()),
            "audit_event_id": body.get("audit_event_id"),
        }
```

- [ ] **Step 5 — register:** in `register_write_tools`, add (after the revoke
  block):

```python
    mcp.tool(
        name="vinctor_issue_grant",
        description=(
            "Operator write action: issue a grant for an agent (agent_id, scopes, "
            "ttl_seconds) via the workspace-key authorized operator endpoint. The "
            "service authenticates, enforces the workspace's issuable-scope bounds "
            "and max TTL, and audits the issuance (returns audit_event_id); the MCP "
            "server mints nothing. Output is allowlist-shaped and omits raw keys, "
            "hashes, and service internals."
        ),
    )(tools.issue_grant)
```

- [ ] **Step 6 — update the registered-tool-name assertion** in
  `tests/test_mcp_tools.py` (the `sorted(mcp.tools)` list ~line 886-890) to include
  `"vinctor_issue_grant"` (sorts between `vinctor_get_*`/`vinctor_issue_grant` and
  `vinctor_reject...`).
- [ ] **Step 7 — run tests + full suite + ruff; commit** `feat(mcp): opt-in operator issue-grant write tool (Phase 2 complete)`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green.
- [ ] Update `docs/mcp-server.md` (add `vinctor_issue_grant` to the opt-in write
  tools note) + `docs/next-actions.md` (MCP Phase 2 write set complete). Fold into
  the PR.
- [ ] Push branch, open PR (no merge; controller auto-merges after a final
  adversarial review per the march agreement).

## Notes
- Body field VERIFIED against `grant_http.py` `_parse_issue_body`: required exactly
  `{agent_id, scopes, ttl_seconds}`; any extra field → 400 `unexpected field`; no
  `workspace_id` in body, no `ttl` alias. 201 response = grant body + `audit_event_id`
  (same shape revoke returns → `_grant_fields()` + audit_event_id is the right shaper).
- Default-off regression: pin `vinctor_issue_grant` absent when `write_enabled` False.
- Proxy-only + leak-free + workspace-key auth: identical discipline to revoke.
