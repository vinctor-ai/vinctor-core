# Performance

A measured baseline for the local SQLite service, and what actually limits it.
Reproduce with `python tools/loadtest.py` (see the reproduce block at the end).

**Correction.** An earlier revision of this document concluded that "the
throughput ceiling is the audit chain write." That conclusion did not survive a
controlled re-measurement: the curve it explained was an artifact of the
harness's own timer, and the behaviours it attributed to the audit write
reproduce identically on endpoints that never touch the database. The corrected
findings are below, including what the earlier revision got right.

There are **no published SLOs**. These are measurements, not commitments.

## Baseline, as shipped

2026-07-17 · 0.5.0 · Apple M1 (4P+4E cores), macOS 26.5.2, Python 3.11 ·
SQLite backend, pool size 8 · 3,200 requests per run · 5 runs per cell, each
against a fresh server and database · clients in their own processes, one TCP
connection per request (which is what the shipped server enforces — see below).
Numbers are median req/s across runs, with (min–max) because single numbers
lied to us once already.

| Concurrent clients | /v1/enforce | /readyz (control: pool lease + `SELECT 1`) | /healthz (control: no database at all) |
| --- | --- | --- | --- |
| 1 | 2,014 (1,815–2,045) | 4,712 (4,672–4,860) | 4,793 (4,197–4,797) |
| 8 | 2,194 (1,291–2,228) | 6,790 (6,365–6,849) | 7,639 (2,396–7,703) |
| 32 | 2,720 (2,515–2,945) | 2,810 (2,726–2,827) | 2,831 (1,530–2,868) |

Every one of the 304,000 requests across the full experiment returned HTTP 200,
every audit chain verified gapless afterwards, and the audit row count matched
`bootstrap + warmup + measured` exactly (the count check matters: a chain whose
newest rows are deleted still *verifies*, so `verify_chain` alone cannot see a
self-consistent tail loss).

Enforce latency in the shipped configuration: p50 0.47 ms / 0.58 ms / 7.4 ms at
1 / 8 / 32 clients; p99 ~1 ms / 40–89 ms / 73–119 ms.

## What limits it

Three different things, depending on regime — established by varying one lever
at a time, not by reading the code and narrating.

**1. At high client counts, per-request connections are the ceiling — for
everything.** At 32 clients, `/v1/enforce` (2,720), `/readyz` (2,810) and
`/healthz` (2,831) converge on the same number. `/healthz` touches no database
and takes no pooled connection (`DATABASE_FREE_PATHS`,
`src/vinctor_service/local_http.py`), so whatever caps all three identically is
not the database: it is connection churn. The handler speaks HTTP/1.0 and
closes the connection after every response even when the client asks for
keep-alive (verified: `will_close` on every response, five TCP connects for
five keep-alive requests), so every request pays a TCP handshake plus a fresh
`ThreadingHTTPServer` thread, against a listen backlog of 5 (socketserver's
default). The max-latency fingerprint confirms it: at 32 clients the DB-free
endpoints show ~1,059–1,063 ms maxima in nine of their ten runs (the tenth:
2,027 ms, i.e. two timeouts) — the ~1 s TCP SYN-retransmission timeout, not
queueing for any lock. (The earlier revision
attributed its "~1 s worst case" to clients queueing for SQLite's write
reservation. The same ~1 s shows up on `/healthz`.)

**2. With connection churn removed, the enforce path is CPU-bound, not
write-lock-bound.** A diagnostic mode (`--keepalive`, which also flips the
handler to HTTP/1.1 for the run — *not* the shipped configuration) reuses one
connection per client:

| Cell (8 clients) | Throughput | p99 |
| --- | --- | --- |
| /healthz, keep-alive | 14,840 (14,543–15,183) | 1.4 ms |
| /v1/enforce, keep-alive, pool 8 | 2,814 (2,786–2,963) | 40–61 ms |
| /v1/enforce, keep-alive, pool 1 | 3,824 (2,961–4,010) | 3–7 ms |

The transport can carry ~15k req/s; enforce caps at ~2.8–4.0k. The gap is the
enforce path itself: parsing, agent-key auth, grant lookup, decision, audit
append, response — 0.22–0.26 ms of server CPU per request across every
keep-alive enforce cell, with the server at ~0.9 CPU-cores when it peaks
(throughput × CPU-per-request ≈ cores observed). That is one Python process executing
mostly-GIL-serialized request code, saturating roughly one core's worth of
work. No single component of it is the wall.

**3. The serialized writes are real — and they are the *tail-latency* source
under the default pool, plus a throughput tax. They are not the ceiling.**
Every enforce request performs *two* serialized SQLite writes, each taking the
write reservation via `BEGIN IMMEDIATE`: the key's `last_used_at` touch
(`src/vinctor_service/keys.py`, `get_by_raw_key`) and the audit chain append
(`src/vinctor_service/sqlite.py`, `SQLiteAuditWriter.write`). With the default
pool of 8 connections these writers contend across connections for the
reservation; with pool size 1 the same writes serialize through one connection
with none of that contention. Measured at 8 clients (including interleaved
A/B runs to rule out ordering): pool 1 beats pool 8 on enforce throughput in
every pairing, by ~10–49%, and cuts enforce p99 from 40–89 ms to 3–7 ms on
both transports. At 32 keep-alive clients the two are indistinguishable
(medians 3,337 vs 3,509 with overlapping spreads). So on this all-write
workload the
earlier revision's clause "the pool adds contention overhead without adding
parallelism for the dominant cost" *is* supported — but the writes never set
the throughput ceiling in any measured cell: holding the audit code constant
and moving a single non-write lever moved enforce throughput by up to 49%
(74% with both levers, at 8 clients), which a serial-write-bound system would
not allow. (Caveat: this workload is 100% write-bearing enforce on one
database. A mixed read workload is what the pool exists for; nothing here
says pool 8 is wrong as a default.)

The Postgres backend serializes audit writes behind one advisory lock — same
design, but its cost is **unmeasured** (Postgres runs only in CI). The earlier
revision presented that as the same measured ceiling; treat it as an untested
hypothesis.

## What the earlier revision got wrong, and how

The published claim was: one client is the fastest configuration (1,847 req/s),
throughput declines with concurrency (1,505 at 32), therefore a fully
serialized bottleneck, therefore the audit write. Two separate errors:

1. **The timer measured the harness.** The timed window wrapped
   `ProcessPoolExecutor` construction, so every spawned worker's interpreter
   start and imports landed inside it — a cost that grows with worker count and
   so manufactures exactly a "declining" curve. Re-run on the same machine, same
   day: the old harness reports 1,428 / ~1,770 / 920–1,486 req/s at 1 / 8 / 32
   clients; the fixed harness (workers spawn, import, connect and warm up
   *before* a start barrier; the clock stops on the last worker's done-token)
   reports 2,014 / 2,194 / 2,720. The curve *rises* with concurrency. The
   original shape — the entire evidential basis for "fully serialized
   bottleneck" — was the artifact.
2. **The attribution was never tested.** "The code contains a serializing
   write" was read as "the write is the measured ceiling," with no cell that
   could distinguish the audit write from connection setup, server CPU, or the
   harness itself. The control endpoints above are that missing cell, and they
   refute the attribution: the ceilings and the ~1 s tails reproduce without
   the database.

Also worth saying plainly: a single closed-loop client measures round-trip
latency (0.47 ms → ~2,000 req/s), not server capacity. "One client is fastest"
was never a statement about a ceiling.

What survives from the earlier revision: #150's pool was not a req/s win (pool
1 matches or beats pool 8 here); the chain write design is genuinely
single-file (that is a code fact, and its measured cost is the pool-contention
tail above); and the method notes below.

## Method, and the traps

`tools/loadtest.py` measures one configuration per invocation and verifies its
own levers: it fails the run if any request is non-200, if the audit chain does
not verify, if the audit row count is not exactly `bootstrap + warmup +
measured` on a clean enforce run, or if the TCP connect count contradicts the
requested connection mode. `--endpoint healthz|readyz|enforce` is the
attribution ladder; `--keepalive` and `--pool-size` are the levers; `--repeat`
reports every rep so the spread is visible. Pool size is injected by
substituting a size-pinning wrapper for `SQLiteServicePool` during setup and
verifying `handle.sqlite_pool.size` afterwards, because `prepare_local_service`
does not expose it; no library code changes for the benchmark's convenience.

Traps this file exists to remember:

* **Don't run the load generator in the server's process.** The service is a
  threaded Python server; its threads share one GIL, and that belongs in the
  number. A load generator in the same process contends for the same GIL and
  gets counted as server latency. An early harness did this and reported
  throughput collapsing 3.4× past 8 clients — the harness measuring itself.
* **Don't let the timed window contain anything but the work.** The second
  harness fixed the GIL trap and then timed its own worker spawning and
  imports, producing a confident, wrong, *published* conclusion. Pre-create
  workers, release them with a barrier, stop the clock on the last completion
  signal, and report setup time separately.
* **Per-request connections at high client counts measure the connect path.**
  Uniform ~1 s maxima are SYN retransmissions against a full accept backlog,
  not application queueing. With this server that transport *is* the shipped
  reality (HTTP/1.0, close per response, backlog 5), so measure it — but
  attribute it to transport.
* **Never publish one number.** One rep in five occasionally collapsed 2–3×
  (e.g. /healthz at 8 clients: median 7,639, min 2,396) for reasons external to
  the code under test. Median with (min–max) over ≥5 fresh-server runs, or it
  didn't happen.

## Why this is not a CI gate

Shared CI runners cannot produce stable throughput numbers, and a perf gate
that flakes is one everyone learns to ignore within a week. Correctness under
load *is* gated — `tests/test_local_http_concurrency.py` hammers a real service
and asserts no drops, no 5xx, no lock errors. This document and the tool are
for deliberate comparison: run it on a machine you control, against two
revisions, and read the difference.

## Reproduce

```sh
# Baseline table (per endpoint, per client count):
python tools/loadtest.py --endpoint enforce --workers 8 --requests 3200 --repeat 5
python tools/loadtest.py --endpoint healthz --workers 8 --requests 3200 --repeat 5
python tools/loadtest.py --endpoint readyz  --workers 8 --requests 3200 --repeat 5

# Transport diagnostic (keep-alive; flips the handler to HTTP/1.1 for the run):
python tools/loadtest.py --endpoint enforce --workers 8 --requests 3200 --repeat 5 --keepalive

# Write-contention lever:
python tools/loadtest.py --endpoint enforce --workers 8 --requests 3200 --repeat 5 --pool-size 1
```
