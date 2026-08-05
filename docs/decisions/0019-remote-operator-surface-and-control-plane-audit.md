# ADR 0019: Remote operator surface, and control-plane actions are audited

## Status

Accepted. 2026-07-17.

## Context

Vinctor's operator controls have no remote surface, and nobody decided that.

The three enforcement mandates (`require_boundary`, `require_subject_token`,
`require_pop`), issuable scope bounds, policy apply/rollback, key rotation, and
audit verify/head are reachable **only** through the CLI, and the CLI opens a
SQLite file:

- `src/vinctor_service/cli.py` contains **zero** occurrences of "postgres" and
  **15** calls to `_sqlite_service(args.db)`.
- The HTTP dispatch table (`src/vinctor_service/local_http.py`) has no route for
  any of them. Its routes are: `/healthz`, `/readyz`, `/metrics`,
  `/v1/enforce`, `/v1/enforce/delegated`, `/v1/simulate`, `/v1/observe`,
  `/v1/tokens`, `/v1/boundaries`, `/v1/auto-approval-rules`,
  `/v1/grant-requests`, `/v1/grants`, `/v1/audit-events`,
  `/v1/service/audit/auth-failures`.

Two consequences follow, neither of which was chosen:

**Postgres cannot be operated.** ADR 0018 is titled "Complete the Postgres
control-plane backend" and it delivered exactly what it said: the repository
contracts. "Control plane" silently meant the storage layer rather than the
surface an operator touches. So on the backend built specifically to unblock
multi-instance production, an operator cannot enable a single mandate, apply
policy, rotate a key, or verify the audit chain with shipped tooling. The
Postgres repositories exist and are correct; nothing reaches them.
`docs/deployment/postgres.md` half-notices this and hands the operator a Python
snippet to bootstrap keys — a workaround documented for one case without anyone
noticing it generalises to the entire operator surface.

**"Operator" means "a person with a shell on the box."** There is no remote
administration on any backend, and a hosted tier has no operator surface to
expose.

Separately: **control-plane changes are not audited at all.** The settings
repository takes only a connection —
`SQLiteAgentEnforcementSettingsRepository.__init__(self, conn)` — so it has no
audit writer and structurally cannot record anything. `set_require_boundary` is
a bare `INSERT`. The same holds for scope bounds, policy apply/rollback, and key
rotation. Every `event_type` the chain carries — `action_permitted`,
`action_denied`, `action_would_deny`, `grant_issued`, `grant_revoked`,
`grant_requested`, `grant_request_auto_approved`, `grant_request_rejected` — is
a record of what an agent did or asked for. Nothing records **who changed the
rules**.

That gap has a specific shape. An attacker who obtains operator authority can
disable `require_boundary`, widen an agent's bounds, and then act — and every
subsequent action is recorded as `action_permitted`, correctly, because it *was*
covered by the rules as they then stood. The audit log truthfully reports that
everything was permitted. The rule change that made it so leaves no trace. For a
product whose claim is a central, revocable, **audited** authority, the log
answers "was the rule followed?" and cannot answer "who changed the rule?".

## Decision

**1. The remote operator surface is an authenticated HTTP API, not a database
connection string.**

Operator actions get HTTP routes, authenticated with a workspace/operator key.
Remote administrators hold a key, not a DSN.

Rejected: giving the CLI a Postgres branch so `vinctor --dsn postgres://…` works
remotely. It satisfies "remote people can change settings" at a price we will not
pay: anyone able to run those commands holds direct database credentials, and a
principal who can write the database can rewrite the audit chain —
`DELETE FROM audit_events WHERE seq > N` leaves a contiguous chain that
`verify_chain` reports as `ok=True` (see the tail-truncation issue). It would
make every remote operator capable of destroying the evidence the product exists
to produce. The CLI's direct-DB path remains for the single-box case; it is not
the answer to remote administration.

**2. Control-plane actions are audited.**

Every mutation of the rules — mandate toggles, scope bounds, policy apply and
rollback, key rotation — writes an audit event. This is part of the surface, not
a follow-up to it: the API widens who can change the rules from "whoever has a
shell" to "whoever has a key", and shipping that reach without recording it
would put a remote hole in the product's central claim.

**3. Control-plane events share the decision chain, distinguished by an
`event_class` field (`control` / `decision`).**

One chain, because the ordering between a rule change and an action **is** the
evidence. Two chains are two clocks: each verifies internally while proving
nothing about their relative order, which is precisely the question an auditor
has after a compromise ("was the boundary disabled before or after this?"). With
one chain, `seq` answers it.

The real costs of one chain are volume and access, and they are answered by the
category field rather than by splitting:

- Every enforce writes a row (a load test produced 300k), while control events
  arrive a handful per day. `event_class` lets retention, export, and access
  policy differ per category without the chain differing.
- It also gives the anchor its first worthwhile use: control events are
  low-volume and high-value, so they can be pushed to an external sink in real
  time at negligible cost, which partially mitigates tail truncation for exactly
  the events an attacker most wants gone.

This follows the shape used where ordering must be provable: Postgres's WAL
carries DDL and DML in one stream so they can be replayed in order; CloudTrail
puts management and data events in one trail and separates them by category and
enablement rather than by log.

## Consequences

- **This is a surface, not a feature.** It is the gap between prototype and
  product, and it sits ahead of PKA-32 (the GA gate): promising API stability
  over a control plane that cannot be reached is not a promise worth making.
- **The hosted tier depends on it.** Cloud customers cannot be handed a shell or
  a DSN, so until this exists there is no operator story to sell.
- **A new authorization question appears**: what may an operator key do, and is
  operator authority itself scoped per workspace? The direct-DB CLI never had to
  answer this because filesystem access *was* the authorization. The API must
  answer it explicitly.
- **The settings repositories change shape.** They currently take a connection
  and nothing else; auditing their writes means they must reach an audit writer,
  and the write plus its audit event must be atomic — a rule change that lands
  without its audit row would be worse than one that isn't audited at all,
  because it would look complete.
- **The API is a new unauthenticated-adjacent attack surface** and inherits the
  rate limiter, the no-disclosure invariants, and the fail-closed discipline of
  the existing routes.
- **`event_class` is an audit schema change** on both backends, and the chain's
  canonical event JSON feeds `row_hash` — so it needs the same care as any other
  chain-affecting migration.
- Both backends, in one pass. A SQLite-only operator API would recreate the exact
  defect this ADR exists to close.

## Notes

Found 2026-07-17 by an independent architecture synthesis, which framed three
apparently separate findings — the operator has no remote surface, the auditor
cannot verify the log, the anchor has no independent sink — as one gap: *the
control exists in the repository layer and has no way to reach the person who
needs it*. This ADR settles the first. The other two are tracked separately and
share the diagnosis.
