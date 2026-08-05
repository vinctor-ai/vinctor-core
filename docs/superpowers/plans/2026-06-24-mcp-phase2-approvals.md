# MCP Phase 2 (E) — operator approval write tools (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Extend the read-only MCP control plane into the **safe core** of the
Phase 2 approval interface: opt-in `vinctor_approve_grant_request` /
`vinctor_reject_grant_request` write tools that proxy the existing
workspace-key-authed operator endpoints (`POST /v1/grant-requests/{id}/approve` /
`/reject`). The read side (`list_grant_requests`, `get_grant_request`,
`list_grants?status=active`) already exists as read-only tools. (Deferred:
`grants.revoke` — needs a new HTTP endpoint — and `grants.issue`.)

**Design (locked):**
- **Opt-in write-mode, default off → read-only behavior byte-for-byte unchanged.**
  A new config flag `write_enabled` (`VINCTOR_MCP_WRITE`, truthy "1"/"true",
  default False). Write tools are registered ONLY when enabled; otherwise only the
  existing read-only tools are registered (today's behavior).
- **Auth:** reuse the existing workspace key (`VINCTOR_MCP_WORKSPACE_KEY`) — the
  operator credential, already distinct from agent runtime keys. No new credential.
- **Security is the service's:** the operator endpoints authenticate (workspace
  key), audit every approve/reject (`audit_event_id` returned), and enforce that
  execution agents cannot approve their own requests (ADR 0004). The MCP only
  proxies; it never mints grants or moves auth state locally.
- **Output:** allowlist-shape the decision response with the EXISTING field sets
  (`GRANT_REQUEST_SAFE_FIELDS`/`fields_for_mode` + `GRANT_SAFE_FIELDS` for the
  issued grant) — never raw keys/hashes/internals; include the safe
  `audit_event_id`.

**Invariants:** default-off = no write tools registered, read-only unchanged.
Writes go only through the workspace-key operator endpoints (service audits +
authorizes). Output allowlist-shaped (no leak). Repo
`/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/mcp-phase2-approvals`, main human-merge-only. Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: config flag + service_client approve/reject

**Files:** `src/vinctor_mcp_server/config.py` (`write_enabled`),
`src/vinctor_mcp_server/service_client.py` (approve/reject), the
`ReadOnlyVinctorClient`/client Protocol in `tools.py`; tests
`tests/test_mcp_*` (mirror the existing MCP client tests).

- [ ] **Step 1 — failing tests:** `load_config` parses `VINCTOR_MCP_WRITE`
  (default False; "1"/"true" → True); `VinctorServiceClient.approve_grant_request(
  "grq_x", reason="ok")` issues `POST /v1/grant-requests/grq_x/approve` with the
  `X-Workspace-Key` header and the reason in the body; `reject_grant_request`
  likewise to `/reject`. (Use the existing connection-factory mock pattern from the
  current client tests.)
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — config:** add `write_enabled: bool = False` to `VinctorMcpConfig`;
  `load_config` sets it from `VINCTOR_MCP_WRITE` via a truthy parse (mirror the
  output-mode parse). Keep all existing fields.
- [ ] **Step 4 — client:** add to `VinctorServiceClient`:

```python
    def approve_grant_request(self, request_id: str, *, reason: str | None = None) -> dict[str, Any]:
        return self._request_json(
            "POST", f"/v1/grant-requests/{_path_part(request_id)}/approve",
            body=_decision_body(reason),
        )

    def reject_grant_request(self, request_id: str, *, reason: str | None = None) -> dict[str, Any]:
        return self._request_json(
            "POST", f"/v1/grant-requests/{_path_part(request_id)}/reject",
            body=_decision_body(reason),
        )
```

  where `_decision_body(reason)` returns the body shape the endpoint's
  `_decision_reason(body)` parser expects — VERIFY the exact field name in
  `grant_request_http.py` (`_decision_reason`); it is likely `{"reason": reason}`
  or `{"decision_reason": reason}`, and an empty/None reason should send `{}` (or
  whatever the parser accepts as "no reason"). Add the two methods to the client
  Protocol used by the write tools.

- [ ] **Step 5 — run tests + full suite + ruff; commit** `feat(mcp): config write_enabled + service_client approve/reject`.

---

### Task 2: opt-in write tools + registration

**Files:** `src/vinctor_mcp_server/tools.py` (write tool methods +
`register_write_tools`), `src/vinctor_mcp_server/server.py` (register when
enabled); tests `tests/test_mcp_*`.

- [ ] **Step 1 — failing tests:**
  - with `write_enabled=False`, building the server registers ONLY the existing
    read-only tools (no `vinctor_approve_grant_request`/`reject` registered) —
    read-only behavior unchanged.
  - with `write_enabled=True`, the two write tools are registered.
  - `approve_grant_request("grq_x", reason="ok")` calls the client and returns an
    **allowlist-shaped** result: includes `audit_event_id` and the shaped
    grant-request/grant fields, and contains NO raw key/hash/internal field even
    if the (mocked) service response includes such keys (mirror the existing MCP
    leak-hunt test).
  - `reject_grant_request(...)` likewise.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — write tool methods** (a `VinctorWriteTools` class or add to the
  tools module): `approve_grant_request(self, request_id, reason=None)` →
  `self._client.approve_grant_request(request_id, reason=reason)` → shape the
  response: `{**allowlist_object(body, fields_for_mode(GRANT_REQUEST_SAFE_FIELDS,
  GRANT_REQUEST_DIAGNOSTIC_FIELDS, mode)), "audit_event_id": body.get(
  "audit_event_id")}` and, if `body.get("grant")`, add a `grant` shaped with the
  grant field sets. `reject_grant_request` likewise. (Reuse the exact shaping
  helpers the read tools use.)
- [ ] **Step 4 — `register_write_tools`** (mirror `register_read_only_tools`):
  register `vinctor_approve_grant_request` and `vinctor_reject_grant_request`,
  each with a description that states it is an **operator write action**
  (workspace-key authorized, service-audited, and that execution agents cannot
  approve their own requests).
- [ ] **Step 5 — server wiring:** in `server.py`, after `register_read_only_tools`,
  add `if resolved_config.write_enabled: register_write_tools(mcp,
  resolved_client, output_mode=resolved_config.output_mode)`.
- [ ] **Step 6 — run tests + full suite + ruff; commit** `feat(mcp): opt-in operator approve/reject write tools (Phase 2 safe core)`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green.
- [ ] Update `docs/mcp-server.md` (note the opt-in write tools + `VINCTOR_MCP_WRITE`)
  and `docs/next-actions.md` (MCP Phase 2 safe-core shipped; revoke/issue + Phase 3
  remain). Small doc commit or fold into the PR.
- [ ] Push branch, open PR (no merge; controller auto-merges after a final
  adversarial review per the march agreement).

## Notes
- **Default-off is the regression guard:** with `write_enabled` False, the server
  registers exactly today's read-only tool set — pin with a test asserting the
  write tool names are absent.
- **No new authority:** the MCP never mints/revokes/issues locally; approve/reject
  go through the service's operator endpoints, which audit and enforce
  self-approval prevention. The MCP adds no bypass.
- **Leak discipline:** the decision response is allowlist-shaped exactly like the
  read tools; assert no raw key/hash/internal in the write-tool output.
- Verify the `_decision_reason` body field name before finalizing `_decision_body`.
