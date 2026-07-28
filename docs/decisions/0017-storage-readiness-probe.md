# ADR 0017: Separate process liveness from storage readiness

## Status

Accepted

## Context

`GET /healthz` proves that the HTTP process can respond, but it cannot tell a
load balancer whether the service's durable store is usable. Returning healthy
during a database outage keeps a broken instance in rotation; turning the
liveness check into a database probe can instead cause unnecessary restart
loops.

## Decision

- Keep `/healthz` as a process liveness endpoint.
- Add unauthenticated `GET /readyz` as a traffic-readiness endpoint.
- Make readiness depend on an injected storage probe. SQLite service runtimes
  execute `SELECT 1`; the existing Postgres decision-storage handle exposes the
  same probe contract.
- Return `200` and `status: ready` on success. Return `503` and
  `status: unavailable` when the probe returns false or raises.
- Do not include database paths, DSNs, exception strings, or backend details in
  either response.
- Use `/readyz` for Compose and preview-container health checks.

## Consequences

An orchestrator can remove an instance from traffic during a durable-store
outage without treating the process as dead. This is a prerequisite for safe
multi-instance operation, not by itself a claim that a deployment has database
HA, load balancing, backups, or production-ready secret management.

## Amendment (PKA-117)

The Postgres runtime later regressed this decision: it injected the readiness
probe as `/healthz`'s liveness check, so a Postgres outage failed liveness on
every pod and restarted the fleet — the exact restart loop the Context section
warns about. Two changes restore and enforce the decision:

- `/healthz` performs no backend work on any backend, and the
  `liveness_check` injection hook that allowed the regression is removed
  rather than merely left unused.
- The readiness probe runs under an explicit deadline
  (`VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS`, default 2s) on a single-flight
  worker: a caller waits no longer than its probe's deadline and fails closed
  at it, and a probe flood produces at most one *concurrent* backend query, so
  it cannot amplify a saturated backend. It does not cap the query *rate* —
  there is no result cache — so against a healthy backend each request still
  costs one round-trip. This also delivers what PKA-94 asked for.
- No transient fault may latch `/readyz` at 503: probes are replaced once they
  finish or expire, and a failed thread start records no worker. Converting a
  transient condition into permanent removal from rotation would reintroduce
  this ADR's failure mode on the readiness side.

## Amendment (PKA-146)

The previous amendment restarted the worker "whenever it is not alive", which a
worker blocked inside the backend call is not: it is alive and never returns to
the handoff, so replacing the expired probe left nobody to run it and `/readyz`
latched at 503 anyway, with the backend never asked a second time. Three further
changes:

- The worker is tracked by *availability* (parked on the handoff) rather than
  liveness. An unavailable worker is abandoned and replaced. Abandoning is
  capped, and reaching the cap is reported rather than silent — unbounded
  replacement would trade a latched 503 for a thread and session leak.
- **The cap must not absorb.** A healthy backend has to answer 200 within a
  bounded time however many earlier calls are wedged, and that must not wait on
  one of them being answered. So while any worker is abandoned, a reclaimer
  thread keeps cancelling the calls that blew the bound. Cancellation reaches
  the store over a *new* connection, so it lands as soon as the store is
  reachable — the same property that makes a fresh probe succeed — and the
  wedged calls end, their slots return, and the next probe answers. Reclaiming
  runs on that thread and on no thread that is inside a readiness deadline.
- The backend call is bounded, not only the caller. Postgres readiness runs on
  connections the probe owns, with `connect_timeout`, TCP keepalives,
  `statement_timeout` and `tcp_user_timeout`. SQLite is bounded by
  `interrupt()`: its busy timeout is 5s against a 2s readiness bound, so
  ordinary write contention outlives the deadline and has to be ended rather
  than waited out.
- Shutdown never closes a handle an in-flight probe is using. `close()` cannot
  join a worker the driver is holding, so the resources the probe touches are
  the probe's own and are disposed of by whichever of shutdown and the call
  finishes last. The record of what a probe holds is multi-valued on both
  backends: replacing a wedged worker makes probes overlap, and a single slot
  records only the newest, losing the older one's reservation.

- **Readiness must touch the connection it serves with.** A probe on a
  dedicated connection answers "is the store up", which is not the question
  `/readyz` is asked. The serving connection's usable flag turns false only
  after something has tried to use it, so reporting from it alone answers `200`
  through a dead serving connection. The single `SELECT 1` that closes that
  fail-open is also what reconnects it: a drained instance receives no enforce
  requests, so readiness is the only thing that can heal it.

### The bound each mechanism actually provides

A bound must be enforced by the component that promises it. Three times in this
card a bound was delegated to something that does not guarantee it: a
server-side `statement_timeout` for a client parked on a socket, a
`cancel_safe(timeout=...)` that psycopg discards below libpq 17, and a reclaimer
that trusted `cancel()` to return. What Vinctor enforces itself is the *waiting*
— for a probe and for a cancellation alike — on threads it owns. What the
platform enforces is when wedged work is reclaimed.

### Cancellation is retried until it is confirmed

A cancel opens a *new* connection to send its request, so it fails whenever the
store is down — the normal case during the outage it exists for. "Attempted" and
"succeeded" are therefore tracked separately: only a confirmed cancel lets a
sweep skip a call, while the reuse guard stays pessimistic and never hands on a
connection a cancel was merely attempted against. Treating an attempt as a
success silently kills the retry loop, and with it the property that makes the
cap temporary.

### What this does not bound

**A bounded query cancellation is a requirement of the Postgres backend,
enforced at startup.** `Connection.cancel_safe()` needs psycopg 3.2+ (where it
was introduced) and libpq 17+ (below which its timeout is silently discarded and
psycopg falls back to `PQcancel`, which blocks with no timeout at all). The
check asks psycopg for the capability rather than reading either version,
because either one alone is not the requirement — so a cancel
might never return, the abandoned-worker cap could never drain, and `/readyz`
would latch at 503 through an outage that had already ended.

That condition is what generated five rounds of defects on this card, every one
of them a piece of state meaning "we tried" being read as "it worked":
`is_alive()` on the probe worker, then on the reclaimer, then `is_ready`, then
`cancelling`, then `cancel_in_flight`. Each existed to survive a cancel that
might never return. Requiring libpq 17 removes the condition instead of
surviving it, and the bookkeeping went with it — the alternative was to keep
adding flags to model an unbounded call.

`tcp_user_timeout` remains, as a Linux-only refinement: it bounds how quickly a
black-holed socket fails, not whether recovery happens. Recovery rests on the
cancel, which works on every platform at libpq 17+.

What is still unbounded: a process that never regains contact with its store
keeps up to `MAX_ABANDONED_READINESS_WORKERS` threads and sessions until it is
restarted. The alternative — starting a worker per probe without limit — trades
a bounded leak for an unbounded one, so the cap stays.

Two further gaps in the serving-connection check, both pre-existing rather than
introduced here, but load-bearing for the `/readyz` answer:

- A worker parked on the serving connection's lock is **not** cancellable. It
  has already checked its own probe connection back in, so it is not among the
  calls a sweep can reach; recovery there depends on the wedged enforce
  transaction releasing the lock. It is still bounded, abandonable and capped,
  and 503 is the correct answer while it lasts.
- `_active_connection()` reconnects through `connect_postgres`, which is a plain
  `psycopg.connect(dsn)` with **no `connect_timeout`**. That makes it the one
  input to a `/readyz` answer with no client-side bound of its own. The
  readiness deadline still bounds what the caller waits for; what is unbounded
  is how long the reconnect keeps a worker.
