# Vinctor Runtime-Authorization Dogfooding Summary

Date: 2026-06-22 (covers hands-on dogfooding conducted through 2026-06-21)

Purpose: a single reviewable record of the hands-on dogfooding of Vinctor's
runtime-authorization core — what was exercised, what held, what was found, and
how each finding was dispositioned. Dogfooding here means driving the **real
shipped surfaces** (CLI + HTTP) against **real running services on throwaway
DBs**, not re-running the unit suite. Every fix/decision below is on `main`.

## Rounds at a glance

| # | Round | Scope | Verdict |
|---|-------|-------|---------|
| 1 | Authorization boundary (single workspace) | in-scope permit; action/resource/scope boundaries; cross-agent isolation; issuable-bounds ceiling; TTL expiry; revoke; concrete-request validation; bad-key 401; decision auditing (13 scenarios) | ✅ PASS → **D2** |
| 2 | Codex runtime measurement (codex-cli 0.137.0) | does the hook fire under `codex exec`, so `emitted?` can be measured | `emitted?` **UNMEASURED** (headless `codex exec` does not load plugin hooks on 0.137.0) |
| 3 | Tenant & delegation boundary (multi-workspace) | enforce- and operator-level isolation across two workspaces; delegated/PEP path | ✅ isolation PASS → **D3** |
| 4 | MCP inspection surface | read-only MCP server output policy; adversarial leak-hunt across all 11 tools | ✅ no findings (0 leaks, positive-allowlist holds) |
| 5 | Approval / request flow | auto-approval / manual / reject / duplicate / out-of-bounds, with auditing | ✅ PASS, no findings |
| 6 | Parallel batch (4 areas) | boundary fail-closed · storage lifecycle · scope grammar · policy files | ✅ 3 clean → **policy MED** + LOW notes |
| 7 | ADR 0007 proven path (subject tokens), **live** | mint → present `X-Subject-Token` → proven delegated enforce; fail-closed; no-leak; both runtimes (10 scenarios) | ✅ 10/10 PASS, no defect |

## Per-round detail

### 1 — Authorization boundary (2026-06-21)
Followed `agents-and-grants.md` verbatim (2 agents, bounds, `service serve`,
boundary, grants). The security core held comprehensively: in-scope → permit;
out-of-scope action/resource/scope → deny; **cross-agent isolation** (agent-A key
+ agent-B grant, both directions) → deny "grant_ref does not belong to the
requesting agent"; issuable-bounds ceiling at issue → 403
`scope_outside_issuable_bounds`; TTL expiry → deny "is expired"; revoke → deny
"is revoked" (distinct reasons); wildcard request → 400 `scope_invalid`; bad key →
401. **Finding D2:** rejections that fail *before* grant-scope evaluation were not
audited at all (cross-agent misuse, auth failure, out-of-bounds issuance) — a real
observability gap for a security product.

### 2 — Codex measurement
Reverse-engineered the codex 0.137.0 plugin/marketplace format and built a valid
logging hook plugin; under `codex exec` the shell tool ran but the hook never
fired (zero hook-load/execute lines at debug log level). Conclusion: headless
`codex exec` does not load/run plugin PreToolUse hooks on 0.137.0; the `emitted?`
coverage cells stay **unmeasured** (not a false "no").

### 3 — Tenant & delegation
Two workspaces in one DB. Enforce-level and operator-level isolation both held
(cross-workspace grant use → deny; cross-workspace operator reads → empty/404/403;
bounds are workspace-scoped). **Finding D3:** the delegated `/v1/enforce/delegated`
path + PEP keys were implemented and unit-tested but **not runtime-wired or
provisionable** (the served runtime didn't resolve PEP keys; no CLI to create one).

### 4 — MCP inspection
The read-only MCP server (11 stdio tools) shapes every output through a positive
allowlist. Adversarial input stuffed with raw keys / hashes / commands / prompts:
**0 sensitive leaks** in both `safe` and `diagnostic` modes; diagnostic exposes
exactly the documented diagnostic fields and nothing more. No findings.

### 5 — Approval / request flow
Full operator workflow (`agent requests create` → `operator requests evaluate` /
`approve` / `reject` → issuance → `agent enforce`). Auto-approval, manual review,
rejection, re-decide-guard, and out-of-bounds approval all behaved correctly; the
out-of-bounds approval produced a `grant_issue_rejected` audit event (confirming
the rejection-audit decision fires through the approval path too). No findings.

### 6 — Parallel batch (4 areas)
- **Boundary fail-closed — PASS.** disabled → `boundary_inactive`, unknown →
  `boundary_not_found`; audit records boundary + reason; no leak. *LOW:* boundary
  is opt-in per request (omit `X-Vinctor-Boundary-Id` → no boundary check) — no
  server-side mandatory-boundary control.
- **Storage lifecycle — PASS, clean.** backup/restore byte-perfect; reset/restore
  require `--yes`, backup `--force`; migrate idempotent; raw keys never plaintext
  (only SHA-256 hash + benign label).
- **Scope grammar — PASS, clean.** terminal `*` = segment-aware prefix (covers
  descendants, not the bare prefix); 2-layer rejection (400 grammar vs 403 bounds).
  *LOW:* `agent enforce -o json` emits two JSON objects on a deny.
- **Policy files — one MED defect.** `operator policy apply` was **non-atomic** (a
  valid bound preceding a later invalid entry committed before the error → partial
  apply). *LOW:* export emits `max_ttl_seconds` where input used `max_ttl`.

### 7 — ADR 0007 proven path (live, 2026-06-21)
Live end-to-end against `local start` (:8821) and `service serve` (:8822) on a
throwaway DB, real wall clock. **10/10 PASS, no defect:** proven permit +
`identity_proven=true`/`token_id` audit; CLI `agent token mint` output; no-token
legacy path unchanged; wrong-audience / subject-mismatch / garbage-token all 403;
expired token (real `--ttl 1` + elapsed time) → 403; **no-leak** — 12 raw secrets
absent from audit (list + export) and from the SQLite binary, only `vtk_` ids
present; cross-workspace isolation → 403; proven path reachable on **both**
runtimes (including the net-new `local start` PEP wiring). Findings all LOW /
by-design (see residuals).

## Findings → disposition

| Finding | Severity | Disposition |
|---------|----------|-------------|
| **D2** — pre-grant rejections un-audited | MED-HIGH | **ADR 0008** (Accepted) + implemented + reconciled — `#51`/`#53`/`#54` (merged) |
| **D3** — delegated/PEP path not runtime-wired or provisionable | gap | `#52` (merged): wired the PEP resolver in `serve` + `operator keys rotate pep` |
| **policy apply non-atomic** (partial apply) | MED | `#55` (merged): validate the whole document before any write (all-or-nothing) |
| **boundary opt-in / no mandatory-boundary control** | LOW (design) | **ADR 0009** Accepted direction B (`require_boundary`, opt-in) — `#56`/`#57` (merged); implementation pending |
| Codex `emitted?` | — | documented as unmeasured in the coverage matrix |
| `agent enforce -o json` double-object on deny | LOW (cosmetic) | open (recorded) |
| policy export `max_ttl_seconds` vs input `max_ttl` | LOW (cosmetic) | open (round-trip still faithful) |
| empty `X-Subject-Token` → unproven path | LOW (by-design) | correct (empty = no claim; not fail-open). Note: a future `require_subject_token` flag must treat empty == absent → deny |

## Confirmed strengths (now regression-locked by tests)

Cross-agent and cross-workspace **isolation** · scope/action/resource boundaries ·
issuable-bounds **ceiling** · TTL expiry and revoke with **distinct reasons** ·
boundary **fail-closed** (disabled/unknown) · MCP **positive-allowlist
non-disclosure** (holds against adversarial input) · storage backup/restore
**byte-perfect** with destructive-op guards and no secret leak · scope grammar
(segment-aware wildcard, two-layer rejection) · the full approval workflow · and
(ADR 0007) the **proven on-behalf-of path** — Vinctor-minted, grant-bound,
audience-scoped tokens with fail-closed verification and no raw-token leak.

## Residual open items (LOW, unfixed)

- `agent enforce -o json` emits two JSON objects on a deny (stderr error line +
  stdout decision) — naive single-stream parsers may trip.
- `operator policy export` emits `max_ttl_seconds` where the input used `max_ttl`
  (round-trip remains faithful).
- The deferred ADR 0007 hardening: mTLS/DPoP proof-of-possession, single-use /
  per-action tokens, explicit token revocation, and a `require_subject_token`
  enforcement flag (mirrors ADR 0009; must treat an empty token header as absent).

## Remaining untested live

- **Hermes runtime boundary measurement** — feasibility uncertain (backlog).
- **Claude Code real-use** — requires interactive `claude -p` driving of the
  hook → enforce loop (not autonomously reproducible).

## Methodology notes

Each round used a throwaway temp directory + SQLite DB on a unique port, the
shipped `vinctor` CLI and raw HTTP (`curl`) for HTTP-only endpoints
(`/v1/enforce`, `/v1/enforce/delegated`, `/v1/tokens`), and was torn down
afterward (service killed, temp removed). Several rounds were run as parallel
sub-agent fan-outs that returned schema-validated findings. Claims are kept honest:
"unmeasured" / "deferred to unit coverage" are valid results and are recorded as
such rather than overstated.
