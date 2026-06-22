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
| 8 | ADR 0009-B `require_boundary` (per-agent), **live** | operator enable/disable/show; hardened absent→`boundary_required`, valid→permit, empty→`boundary_not_found`; default-off unchanged; **disable kill-switch now effective**; both runtimes (8 scenarios) | ✅ 8/8 PASS, no defect |

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

### 8 — ADR 0009-B `require_boundary` (live, 2026-06-22)
Live end-to-end against `local start` (:8831) and `service serve` (:8832), real
wall clock. **8/8 PASS, no defect.** Default-off in-scope enforce → permit
(unchanged); `operator require-boundary enable <agent>` → absent-boundary enforce
→ 403 `boundary_required`; with a valid active boundary → permit (the flag only
closes the absent gap); empty/whitespace header → `boundary_not_found` (never
normalized to absent, never permit — no fail-open); toggle `disable` restores
permit and `show` tracks state; the flag works on **both** runtimes (live-read
from the shared DB by `service serve`). **Headline — the `disable` kill-switch is
now effective:** against a *disabled* boundary, an **unhardened** agent that drops
the header still permits (the classic bypass, by design/default-off), but a
**hardened** agent that drops the header is denied `boundary_required` — it can no
longer evade the disabled boundary by omitting the header. Audit records the
`boundary_required` deny with the correct reason; full-DB scan found zero raw-key
occurrences. F1 (informational, NOT a server bug): reproducing the empty-header
case with `curl -H "X-…:    "` is misleading because curl drops whitespace-only
headers before sending; verify at the server level (e.g. Python `http.client`),
where whitespace values correctly yield `boundary_not_found`.

## Findings → disposition

| Finding | Severity | Disposition |
|---------|----------|-------------|
| **D2** — pre-grant rejections un-audited | MED-HIGH | **ADR 0008** (Accepted) + implemented + reconciled — `#51`/`#53`/`#54` (merged) |
| **D3** — delegated/PEP path not runtime-wired or provisionable | gap | `#52` (merged): wired the PEP resolver in `serve` + `operator keys rotate pep` |
| **policy apply non-atomic** (partial apply) | MED | `#55` (merged): validate the whole document before any write (all-or-nothing) |
| **boundary opt-in / no mandatory-boundary control** | LOW (design) | **ADR 0009-B implemented (per-agent)** — `#56`/`#57`/`#60` (merged); live dogfood 8/8 PASS (round 8). The `disable` kill-switch is now effective for hardened agents |
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
audience-scoped tokens with fail-closed verification and no raw-token leak · and
(ADR 0009-B) **opt-in mandatory boundary** — a per-agent `require_boundary` that
makes the `disable` kill-switch un-evadable (an absent boundary on a hardened
agent fails closed) while leaving the default-off path unchanged.

## Residual open items (LOW, unfixed)

- `agent enforce -o json` emits two JSON objects on a deny (stderr error line +
  stdout decision) — naive single-stream parsers may trip.
- `operator policy export` emits `max_ttl_seconds` where the input used `max_ttl`
  (round-trip remains faithful).
- The deferred ADR 0007 hardening: mTLS/DPoP proof-of-possession, single-use /
  per-action tokens, explicit token revocation, and a `require_subject_token`
  enforcement flag (mirrors ADR 0009; must treat an empty token header as absent).

## Remaining untested live

The autonomously-runnable dogfooding is complete (rounds 1–8 cover every shipped
runtime-authorization surface). What remains cannot be driven autonomously here:

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

Harness caveat (round 8): `curl` drops whitespace-only request headers before
sending, so an empty/whitespace `X-Vinctor-Boundary-Id` reproduced via `curl`
looks truly-absent to the server. Verify header-value edge cases with a client
that does not trim (e.g. Python `http.client`).
