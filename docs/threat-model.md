# Vinctor Threat Model

> Status: living document. Tracks what each Vinctor phase defends and, more
> importantly, what it does **not**. This document is deliberately conservative:
> if a control is bypassable, that is stated plainly. It exists so that a CISO
> or security reviewer can trust the boundaries we draw rather than discover
> them.

## CONTEXT (why this document exists)

Vinctor is runtime authorization for AI agents: a deterministic decision core
(`vinctor_core`) plus a thin service layer (`vinctor_service`) that issues
scoped, time-bounded, revocable grants and answers "given an active grant, an
action, and a resource, should this action be permitted?".

A security control is only useful if its boundary is honest. An AI agent is a
powerful, partially-trusted, and sometimes adversarial principal; some of the
ways an agent can act are simply not visible to a given enforcement point. This
document states, per phase, the **honest one-line claim** and the explicit
**what we do NOT claim** list, so that nobody — operator, design partner, or
CISO — over-relies on a control that does not cover their threat.

The phasing here matches the rest of the repository:

- **Phase 1** — agent-side runtime hook (cooperative enforcement at the agent).
- **Phase 1.8** — resource-side PDP/PEP, delegated enforcement
  (see [ADR 0007](decisions/0007-delegated-enforce-and-pep-identity.md)).
- **Phase 2** — credential brokering (NOT built).

Invariants preserved across all phases: **fail-closed** (ambiguity or
infrastructure failure denies, never permits), **non-disclosure** (decisions
never leak `grant_ref`, internal ids, prompts, or raw tool input), and
**tenant isolation** (a workspace can only act on its own grants).

## Trust boundaries and assumptions

| Element | Trust posture |
| --- | --- |
| Vinctor decision core + service | Trusted. Deterministic, fail-closed, audited. |
| The AI agent / model | Partially trusted to adversarial. May be prompt-injected, jailbroken, buggy, or fully compromised. |
| The agent runtime (Claude Code, Codex, etc.) | Trusted only to the extent it actually invokes the configured boundary before executing a tool. |
| The host the agent runs on | Out of scope as a control surface. Ambient host credentials, env vars, files, and network are reachable by the agent unless an external sandbox constrains them. |
| Operator / workspace admin | Trusted authority. Issues grants, defines rules, runs the service. |
| Resource server (PEP, Phase 1.8) | Trusted to mediate access to its own protected resource and to call Vinctor as the PDP. |

Vinctor does **not** provide sandboxing, OS/process isolation, prompt/content
safety, or provider credential management. Those are explicitly out of scope
for the core (see `README.md`, "What This Core Does Not Own").

## Adversary model

We consider three escalating adversaries:

1. **Mistaken/over-eager agent** — not malicious, but proposes an action
   outside its intended authority (wrong repo, prod deploy, destructive
   command). The common case.
2. **Prompt-injected agent** — content in the agent's context steers it toward
   actions the user never intended. The agent itself is "honest" but its
   instructions are attacker-controlled.
3. **Fully-compromised agent** — the attacker controls the agent process and
   will actively try to bypass any cooperative control. The hardest case.

Each phase below states which adversaries it meaningfully constrains.

---

## Phase 1 — Agent-side runtime hook (cooperative)

A runtime hook (e.g. Claude Code `PreToolUse`) maps a proposed tool call to an
`action:resource` pair and calls `/v1/enforce` before the tool runs. A `deny`
or any failure stops the call.

### Honest one-line claim

> Phase 1 deterministically gates the agent's *cooperatively-surfaced* tool
> calls against scoped, time-bounded grants and fails closed — it raises the
> cost of, and creates an audit trail for, mistaken and prompt-injected
> actions, but it is bypassable by an agent that controls its own runtime.

### What it DOES defend

- **Mistaken and prompt-injected actions (adversaries 1 and 2)** on tools that
  are actually routed through the boundary: a `PreToolUse`-mapped call outside
  the grant's scope is denied before execution.
- **Fail-closed behavior**: if Vinctor is unreachable, the response is
  malformed, or the config is invalid, the mapped call is denied, not allowed
  (see `docs/testing/mock-vinctor-service.md`,
  `docs/operator-policy-authoring/troubleshooting.md`).
- **Time-bounding and revocation**: an expired or revoked grant stops
  permitting, so stale authority is not silently long-lived.
- **Audit trail**: every mapped decision is recorded (permit/deny) without
  leaking secrets or raw tool input, giving operators a reviewable record.
- **Coverage across mapped tool families**: the hook can map command
  execution, file read/write tools, and web tools (WebFetch/WebSearch) where
  the runtime surfaces them as `PreToolUse` events.

### What it does NOT defend / what we do NOT claim

- **It is cooperative and bypassable.** The agent controls its own
  configuration. Disabling, editing, or not installing the hook removes
  enforcement entirely. Phase 1 is a guardrail for a cooperating runtime, not a
  containment boundary against a fully-compromised agent (adversary 3).
- **Ambient host credentials are outside the boundary.** Tokens, API keys, SSH
  keys, cloud profiles, and env vars already present on the host are reachable
  by the agent directly. The hook authorizes *mapped tool calls*; it does not
  strip, broker, or shield credentials.
- **Unwrapped / raw paths are not covered.** Anything the runtime does not
  surface as a mapped `PreToolUse` event — direct syscalls, a subprocess the
  agent spawns that itself acts, a tool the hook does not map — is not seen and
  not enforced.
- **Bash wrapping and chaining bypass.** Command-level mapping operates on the
  surfaced command string. Shell features — pipes, subshells, `eval`, base64 or
  other encoding, here-docs, writing a script and executing it, chaining with
  `;`/`&&`/`|` — can express a denied effect through a string the mapper does
  not classify as that effect. Command mapping is best-effort intent
  recognition, not a sandbox.
- **Jupyter / IDE-MCP execution bypasses `PreToolUse`.** Code executed through
  an IDE-MCP path such as `mcp__ide__executeCode` does not pass through the
  Claude Code `PreToolUse` hook, so it is not gated by Phase 1. This is a known
  uncovered execution channel.
- **Managed/enterprise settings narrow but do not close the bypass.** On a
  managed device, enterprise/managed settings can make the hook
  un-disableable for a non-admin user — meaningfully raising assurance for that
  population. But this does **not** cover: local administrators, third-party or
  alternate runtime providers, unmanaged/BYOD devices, or web/cloud-hosted
  agent surfaces. Those paths remain out of the boundary.
- **No claim** of complete mediation, OS/process isolation, sandboxing,
  prompt/content safety, single-use tokens, full JIT orchestration, credential
  shielding, human approval workflow, or production/hosted enforcement.

### Net assessment

Phase 1 is a **deterrent and detective control** for cooperating runtimes. It
substantially helps with adversaries 1 and 2 on covered tool paths and provides
audit. It does **not** contain adversary 3, and it leaves ambient credentials
and uncovered execution channels (raw paths, shell chaining, IDE-MCP code
execution) outside its boundary.

---

## Phase 1.8 — Resource-side PDP/PEP (delegated enforcement)

A resource server acts as a Policy Enforcement Point (PEP), mediating access to
a protected resource (a git host, a deploy runner, an MCP tool server), and
consults Vinctor as the Policy Decision Point (PDP) for a third-party subject
agent via the additive `/v1/enforce/delegated` path. The PEP authenticates with
its own workspace-scoped `pep_` key; the asserted subject workspace is forced to
the PEP key's own workspace, preserving tenant isolation. See
[ADR 0007](decisions/0007-delegated-enforce-and-pep-identity.md).

### Honest one-line claim

> For an instrumented internal resource whose PEP mediates **every** access path
> and fails closed, Phase 1.8 makes authorization **non-bypassable by the
> agent** — *conditional on* complete mediation, fail-closed behavior, and a
> trusted agent identity, the last of which is currently *asserted* (bearer
> key), not proven.

### What it DOES defend

- **Agent-bypass resistance for instrumented resources.** Because enforcement
  moves to the resource side, an agent cannot remove the control by editing or
  disabling its own hook. A denied subject cannot reach the protected resource
  through the mediated path. This is the key improvement over Phase 1: it
  constrains adversary 3 *with respect to the brokered resource*, not just
  adversaries 1 and 2.
- **Tenant isolation preserved structurally.** A PEP key is workspace-scoped;
  the asserted `workspace_id` is forced to the PEP's own. There is no admissible
  cross-workspace request, so a PEP for workspace A can never authorize a
  subject or grant in workspace B.
- **Non-disclosure preserved.** The delegated response leaks no more than
  `/v1/enforce`; cross-workspace and bad-subject requests fail closed with a
  generic `forbidden`/`grant_not_found` and write no audit event.
- **Honest audit of who-asked vs who-it's-about.** Audit records the enforcing
  PEP principal separately from the subject `agent_id`.

### What it does NOT defend / what we do NOT claim

- **Conditional, not unconditional.** "Non-bypassable" holds **only if** the
  PEP achieves *complete mediation* — every path to the resource goes through
  the PEP — and fails closed. A side door (a second credential, a direct
  network path, an un-instrumented replica) that does not consult the PDP is not
  covered. Vinctor cannot verify completeness of mediation on the resource side;
  the operator must.
- **Only instrumentable systems.** Resources that cannot host a PEP or be put
  behind one (opaque SaaS, third-party APIs the operator does not control,
  non-instrumentable legacy systems) are **not** covered by Phase 1.8.
- **Ambient credentials still outside the boundary.** If the agent already
  holds a credential that reaches the resource without traversing the PEP, the
  delegated PDP never sees the access. Phase 1.8 governs the *mediated* path; it
  does not remove the agent's other means.
- **Identity is ASSERTED, not proven.** The PEP *asserts* the subject
  `agent_id`. Until the ADR 0007 identity-proof model is selected and landed,
  Vinctor makes **no** claim of proven on-behalf-of identity. The shipped slice
  is a forward-compatible mechanism (PEP key + delegated path + separate audit
  principal) only. How subject identity is *proven* — relayed agent key (weak),
  grant-bound short-lived token (medium), or SSO/federation (strongest), with
  sender-constrained mTLS/DPoP as the hardening direction — is an **OPEN
  DECISION reserved for founder sign-off**.
- **No credential brokering.** The delegated path only reads grants and emits
  decisions. It does not mint, hold, strip, or broker resource credentials
  (Phase 1 posture preserved).
- **No claim** of production/hosted posture, proven agent identity, or coverage
  of non-instrumentable systems or ambient credentials.

### Net assessment

Phase 1.8 is the first control that can be **non-bypassable by the agent** —
but only for instrumented resources with complete mediation and fail-closed
PEPs, and only as strongly as the *asserted* subject identity, which is not yet
cryptographically proven. It does not address ambient credentials or
non-instrumentable systems.

---

## Phase 2 — Credential brokering (NOT built)

Vinctor would broker the credentials an agent uses to reach a resource —
issuing scoped, short-lived, audience-bound credentials at action time and
stripping ambient long-lived credentials from the agent's environment — so that
the agent never holds standing authority of its own.

> Status: **NOT built.** This section describes intent and boundary so the claim
> is not made prematurely. No credential brokering exists in this repository
> (see `README.md`, `docs/deployment/self-hosting.md`: "credential broker —
> Future / not implemented").

### Honest one-line claim (target, not shipped)

> Phase 2 is the only phase that neutralizes a **fully-compromised agent** by
> removing its *means* — and even then only for the credentials Vinctor actually
> brokers, plus whatever ambient credentials are actually stripped from the
> environment.

### What it WOULD defend (when built)

- **Removes standing authority.** If the agent never holds a long-lived
  credential and must obtain a scoped, short-lived, brokered credential per
  action, then compromising the agent does not hand the attacker durable
  access. This is what addresses adversary 3 at the level of *means*, not just
  *mediation*.
- **Ambient-credential stripping.** Removing pre-existing host credentials from
  the agent's environment closes the largest gap left open by Phases 1 and 1.8.

### What it does NOT / WOULD NOT claim

- **It does not exist today.** No part of Vinctor brokers credentials. Do not
  represent Phase 2 capabilities as available.
- **Scope-limited even when built.** It would neutralize a compromised agent
  **only** for brokered credentials and **only** for ambient credentials that
  are actually stripped. Any credential outside the broker's control, any
  non-brokered access path, and any resource the broker cannot front would
  remain reachable.
- **Not a sandbox or a content-safety control.** Even with brokering, Vinctor
  would not provide OS/process isolation, prompt/content safety, or guarantees
  about what the agent does with a legitimately brokered, in-scope credential
  during its validity window.

### Net assessment

Phase 2 is the only phase that targets the agent's *means* rather than its
*mediated actions*. It is **not built**, and even fully realized it is bounded
by which credentials are brokered and which ambient credentials are stripped.

---

## Summary: claim per phase

| Phase | Status | Honest one-line claim | Strongest adversary it constrains |
| --- | --- | --- | --- |
| 1 — Agent-side hook | Shipped (prototype) | Deterministically gates *cooperatively-surfaced* tool calls, fails closed, audits; bypassable by an agent controlling its runtime. | Prompt-injected agent (2), on covered paths. |
| 1.8 — Resource-side PDP/PEP | Mechanism shipped; identity-proof OPEN | Non-bypassable for instrumented resources **iff** complete mediation + fail-closed + trusted identity; identity is asserted, not proven. | Compromised agent (3), w.r.t. the mediated resource only. |
| 2 — Credential brokering | NOT built | Removes the agent's *means*; neutralizes a fully-compromised agent only for brokered creds + stripped ambient creds. | Compromised agent (3), at the level of means. |

## Consolidated "what we do NOT claim" (all phases)

- No complete mediation guarantee for Phase 1 (cooperative, bypassable).
- No OS/process isolation, sandboxing, or containment of a compromised agent in
  Phase 1.
- No coverage of ambient host credentials or unwrapped/raw execution paths in
  Phase 1 or 1.8.
- No defense against bash wrapping/chaining or IDE-MCP (`mcp__ide__executeCode`)
  code execution in Phase 1.
- No coverage of non-instrumentable systems in Phase 1.8.
- No *proven* on-behalf-of agent identity in Phase 1.8 — identity is asserted
  via bearer key until the ADR 0007 identity model lands with founder sign-off.
- No credential brokering, credential shielding, or ambient-credential
  stripping anywhere today (Phase 2 not built).
- No prompt/content safety, no provider credential management, no human approval
  workflow, no single-use/full-JIT orchestration, no hosted/production
  enforcement posture.

## NEXT STEPS (what remains)

- **Close the founder-sign-off OPEN DECISION on agent identity proof** (ADR
  0007): select the relayed-key / grant-bound-token / SSO model and whether
  sender-constrained mTLS/DPoP is mandatory. Until then Phase 1.8's identity
  claim stays "asserted, not proven."
- **Document, per design-partner deployment, the actual completeness of
  mediation** for each instrumented resource, since Phase 1.8's non-bypassable
  claim is conditional on it.
- **Scope a Phase 2 credential-brokering design** (ambient-credential stripping
  + scoped short-lived credential issuance) before any Phase 2 capability is
  represented as available.
- **Revisit IDE-MCP / Jupyter coverage**: track whether the runtime exposes a
  pre-execution boundary for `mcp__ide__executeCode`, which would let Phase 1
  cover that channel.
- Keep this document in sync as phases ship; every new enforcement surface must
  add its honest claim and its "do NOT claim" list here.
