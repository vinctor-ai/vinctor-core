# F — MCP grants.revoke write tool (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Add the opt-in MCP operator write tool `vinctor_revoke_grant`, mirroring
the E approve/reject tools. The HTTP endpoint **already exists** —
`POST /v1/grants/{grant_ref}/revoke` (`grant_http.py:120-138`, workspace-key-authed,
calls `service.revoke_grant`, returns `{...grant fields, audit_event_id}`, 404
`grant_not_found`). F is MCP-only.

**Design (locked):** opt-in under the existing `VINCTOR_MCP_WRITE` write-mode
(default off → unchanged); reuse the workspace key; proxy the existing endpoint;
allowlist-shape the response. No new HTTP endpoint, no new credential.

Repo `/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/mcp-grants-revoke`, main human-merge-only. Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: `vinctor_revoke_grant` (client + tool + registration)

**Files:** `src/vinctor_mcp_server/service_client.py` (revoke_grant),
`src/vinctor_mcp_server/tools.py` (WriteVinctorClient Protocol + VinctorWriteTools
+ register_write_tools); tests `tests/test_mcp_service_client.py` +
`tests/test_mcp_tools.py` + `tests/test_mcp_server.py`.

- [ ] **Step 1 — failing tests:**
  - `VinctorServiceClient.revoke_grant("grt_x")` → `POST /v1/grants/grt_x/revoke`
    with `X-Workspace-Key`, NO body; path is URL-encoded (traversal blocked).
  - `VinctorWriteTools.revoke_grant("grt_x")` → calls the client and returns an
    allowlist-shaped result with the safe grant fields + `audit_event_id`, and NO
    raw key/hash/internal even if the (mocked) service response contains them.
  - with `write_enabled=True`, `vinctor_revoke_grant` is registered; with
    `write_enabled=False` (default) it is NOT registered (read-only unchanged).
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — client** (mirror approve/reject; revoke takes no body):

```python
    def revoke_grant(self, grant_ref: str) -> dict[str, Any]:
        return self._request_json(
            "POST", f"/v1/grants/{_path_part(grant_ref)}/revoke"
        )
```

- [ ] **Step 4 — Protocol + tool:** add `revoke_grant(self, grant_ref: str) ->
  dict[str, Any]` to the `WriteVinctorClient` Protocol; add to `VinctorWriteTools`:

```python
    def revoke_grant(self, grant_ref: str) -> dict[str, Any]:
        body = self._client.revoke_grant(grant_ref)
        return {
            **allowlist_object(body, self._grant_fields()),
            "audit_event_id": body.get("audit_event_id"),
        }
```

  (`_grant_fields()` is the existing shaping helper; the revoke response is flat
  grant fields + `audit_event_id`.)

- [ ] **Step 5 — register:** in `register_write_tools`, add (after reject):

```python
    mcp.tool(
        name="vinctor_revoke_grant",
        description=(
            "Operator write action: revoke an active grant by grant_ref via the "
            "workspace-key authorized operator endpoint. The service authenticates "
            "and audits the revocation (returns audit_event_id); the MCP server "
            "issues nothing. Output is allowlist-shaped and omits raw keys, hashes, "
            "and service internals."
        ),
    )(tools.revoke_grant)
```

- [ ] **Step 6 — run tests + full suite + ruff; commit** `feat(mcp): opt-in operator revoke-grant write tool`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green.
- [ ] Update `docs/mcp-server.md` (add `vinctor_revoke_grant` to the opt-in write
  tools note) + `docs/next-actions.md` (MCP Phase 2: revoke shipped; only
  `grants.issue` + Phase 3 remain). Small doc commit or fold into the PR.
- [ ] Push branch, open PR (no merge; controller auto-merges after a final
  adversarial review per the march agreement).

## Notes
- Default-off regression: pin that `vinctor_revoke_grant` is absent when
  `write_enabled` is False.
- Proxy-only + leak-free + workspace-key auth: identical discipline to the E
  approve/reject tools.
