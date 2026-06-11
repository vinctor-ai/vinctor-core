# Grant lifecycle JIT semantics

- status: accepted
- date: 2026-06-11

## Context

The grant issuance lifecycle now supports service-issued scoped grants with
explicit TTL and revocation. This creates the foundation for future
just-in-time grant flows, but the repository should not accidentally define JIT
as a one-shot token model.

For Vinctor, just-in-time grant issuance is about when authority is issued and
how narrowly it is scoped. A grant should remain meaningful for the work it was
issued for.

## Decision

Do not define JIT grants as single-use tokens.

For Vinctor, "just-in-time" means grants are:

- issued when needed
- scoped to a task, session, or workflow
- time-bounded
- revocable

It does not mean grants are:

- valid for one tool call only
- immediately invalid after first use
- always extremely short-lived

Use these conceptual grant classes:

1. Bootstrap grant
   - local evaluation and dogfooding
   - issued during local service bootstrap
   - useful for a developer session
   - example TTL: several hours
   - current local launcher behavior is closest to this

2. Task grant
   - issued for a specific task or workflow
   - narrower scope than a bootstrap grant
   - valid while the task is being worked on
   - example TTL: 30 minutes to a few hours
   - first realistic future JIT direction

3. Human-approved grant
   - future approval-mediated authority
   - issued after human or operator approval
   - may have a longer TTL than task grants
   - appropriate for higher-risk actions such as production deploys, refunds,
     migrations, or customer-impacting operations
   - approval workflow remains out of scope for the current implementation

The current grant issuance lifecycle should support TTL as a first-class field
and keep revocation support. It should not hardcode a single interpretation of
"JIT = one use".

## Terminology

Use:

- service-issued scoped grants
- time-bounded grants
- revocable grants
- task-oriented grants, only when task metadata is actually present

Avoid for now:

- single-use JIT token
- full JIT orchestration
- least-privilege orchestration
- human approval workflow
- credential shielding

## Consequences

- `ttl_seconds` and persisted `expires_at` remain central to grant issuance.
- Hooks remain enforce-only and continue to consume already-issued
  `grant_ref` values.
- Single-use grants are not implemented unless explicitly planned later.
- The repository may describe this slice as supporting service-issued scoped,
  time-bounded, revocable grants.
- The repository must not claim full JIT least-privilege orchestration,
  credential shielding, or approval workflow support from this slice.
