# 0007 Delegated Enforce And PEP Identity

Date: 2026-06-16

## Status

Accepted for the forward-compatible mechanism. The agent-identity-proof model
(see "Recommendation: agent identity proof") is an **OPEN DECISION** that
requires founder sign-off before any production posture is claimed.

**Runtime wiring (2026-06-21):** the mechanism is now wired into the local
runtime — `vinctor operator keys rotate pep --pep-id <id>` provisions a PEP key,
and `vinctor service serve` resolves PEP keys for `/v1/enforce/delegated`
(previously the contract was implemented and tested but not reachable through the
served runtime). This makes the mechanism usable for local evaluation; it still
makes **no** claim of proven on-behalf-of identity — that (identity proof,
models 1/2/3 below) remains the OPEN DECISION.

**Identity-proof decision (2026-06-21): RESOLVED — Model 2 selected (founder
sign-off) and implemented.** The subject is proven by a Vinctor-issued,
grant-bound, audience-scoped, short-lived token (`vat_`): the agent mints one for
its own grant (`POST /v1/tokens`, `vinctor agent token mint`) and the PEP presents
it via the additive optional `X-Subject-Token` header on `/v1/enforce/delegated`.
When present and valid (token resolves by hash, not expired, audience = the
authenticated PEP, and the token/body/grant agree on the full
`(agent_id, workspace_id, grant_ref)` tuple), the decision is audited
`subject_token_verified=true` with the `token_id`; any failure fails closed (403, never
503, never a fall-through to the unproven path). The legacy no-token path is
unchanged and still makes no proof claim. Models 1 and 3 are not pursued.
mTLS/DPoP proof-of-possession remains the intended hardening (a forward-compatible
extension point, not in this slice). Design:
`docs/superpowers/specs/2026-06-21-adr0007-subject-token-identity-proof-design.md`;
plan: `docs/superpowers/plans/2026-06-21-adr0007-subject-tokens.md`.

## Context

`src/vinctor_core/enforce.py:evaluate_enforce` is identity-agnostic: it answers
"does this grant permit this action on this resource right now?" and never asks
who is calling. That is correct and stays unchanged.

The service contract on top of it is not identity-agnostic. `/v1/enforce`
(`v1_http.py` + `v1_enforce.py`) derives `workspace_id`/`agent_id` from the
caller's `X-Agent-Key` and rejects unless
`grant.agent_id == request.agent_id AND grant.workspace_id == request.workspace_id`.
That equality is the tenant-isolation invariant: an agent can only enforce its
own grants in its own workspace.

The consequence is that a **resource server** (a Policy Enforcement Point, PEP)
cannot ask Vinctor "is agent X authorized for this action?" on behalf of agent
X. The only principal that can check a grant today is the agent that owns it.
A PEP that mediates access to a protected resource (a git host, a deploy
runner, an MCP tool server) has no first-class way to consult Vinctor as the
Policy Decision Point (PDP) for a third-party subject.

We want PEPs to be able to perform **delegated / on-behalf-of enforcement**
without weakening tenant isolation and without prematurely committing to a
particular agent-identity-proof scheme.

## Decision

### 1. A workspace-scoped PEP / resource-server key type

Introduce a third local key type, sibling to `aak_` (agent) and `wsk_`
(workspace):

- prefix: `pep_`
- `key_type`: `resource_server`
- scope: bound to exactly one `workspace_id`, with a stable `pep_id`
  (carried in the existing `agent_id` column for storage; semantically it is a
  PEP principal id, never an agent id).
- hashing/storage: identical posture to existing keys (SHA-256 hash, raw key
  never persisted), per ADR 0006.

A PEP key authenticates the enforcing principal. It does **not** assert any
agent identity by itself.

### 2. A delegated enforce request

Add an additive `/v1/enforce/delegated` path (the existing `/v1/enforce` is
unchanged). The PEP authenticates with its **own** `pep_` key (header
`X-PEP-Key`) and supplies, in the request body, the subject it is asking about:

- `agent_id` — the asserted subject agent
- `workspace_id` — the asserted subject workspace
- `grant_ref`, `action`, `resource` — the access being checked

Authorization rule (replaces `caller == grant.agent_id` for this path only):

> The request is admissible iff the PEP key is **valid and active for the
> asserted workspace**, AND `grant.workspace_id == asserted workspace_id`, AND
> `grant.agent_id == asserted agent_id`.

Tenant isolation is preserved: the asserted `workspace_id` is forced to equal
the PEP key's own workspace. A PEP for workspace A can never authorize a
subject or a grant that lives in workspace B — there is no admissible request
that crosses workspaces. The PDP core (`evaluate_enforce`) still does the
actual permit/deny on the resolved grant.

`/v1/enforce` (caller == agent) is kept exactly as-is. The delegated path is
purely additive.

### 3. Audit records the PEP principal separately from the subject

`build_audit_event` records an optional `enforcing_principal` (the PEP id) that
is **separate** from `agent_id` (the subject). For direct `/v1/enforce`,
`enforcing_principal` is absent (the agent enforces for itself). For the
delegated path it is the PEP id. This keeps the audit trail honest about *who
asked* versus *who the decision is about*.

Non-disclosure invariants are unchanged: the delegated response never leaks
`grant_ref`, internal ids, or tool input beyond what `/v1/enforce` already
returns; cross-workspace and bad-subject requests fail closed with a generic
`forbidden`/`grant_not_found` and write no audit event, exactly like the
existing path.

## Recommendation: agent identity proof (OPEN DECISION — needs founder sign-off)

The mechanism above lets a PEP *assert* a subject `agent_id`. It does **not**
yet prove that the access actually originates from that agent. How the asserted
subject identity is *proven* is deliberately left open. Three models, weakest to
strongest:

1. **Agent relays its own key to the PEP (weak).** The agent hands its
   `aak_` key to the PEP, which forwards it. Simple, but the PEP (and anything
   on the path) now holds a bearer credential for the agent — bad blast radius,
   no sender constraint. Not recommended beyond throwaway demos.
2. **Vinctor-issued, grant-bound short-lived token (medium).** The agent
   obtains from Vinctor a short-lived token bound to a specific grant and
   audience; it presents the token to the PEP, which relays it. The PEP never
   holds a long-lived agent credential, and the token's blast radius is scoped
   and time-boxed. Requires a token-issuance slice.
3. **SSO / federation → agent_id (strongest).** The agent's identity is
   established by an external IdP and federated into a Vinctor `agent_id`, so
   the asserted subject is cryptographically tied to a real principal rather
   than a relayed secret. Highest assurance, highest integration cost.

**Forward direction:** sender-constrained credentials — mTLS or DPoP/PoP-style
proof-of-possession — should be layered on whichever model is chosen, so a
relayed/stolen token cannot be replayed by a different sender. This is noted as
the intended hardening direction, not part of this slice.

This recommendation is **not final**. Selecting model (1), (2), or (3) — and
whether mTLS/PoP is mandatory — is an OPEN DECISION reserved for founder
sign-off. Until then, Vinctor ships only the forward-compatible mechanism
(PEP key + delegated path + separate audit principal) and makes **no** claim of
proven on-behalf-of identity.

## Consequences

- Resource servers can act as PEPs and consult Vinctor as the PDP for a
  third-party subject, without each agent's grant being checkable only by that
  agent.
- Tenant isolation is structurally preserved: a PEP key is workspace-scoped and
  the asserted workspace is forced to its own.
- The audit trail distinguishes the enforcing PEP from the subject agent.
- The hard, security-critical question (how subject identity is *proven*)
  is surfaced explicitly and deferred to founder sign-off rather than decided
  implicitly in code.
- No credential brokering is introduced; the PEP path only reads grants and
  emits decisions (Phase 1 posture preserved).
