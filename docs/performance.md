# Performance

A measured baseline for `/v1/enforce` on the SQLite backend, and what actually
limits it. Reproduce with `python tools/loadtest.py`.

There are **no published SLOs**. These are measurements, not commitments.

## Baseline

2026-07-17 · 0.5.0 · Apple Silicon laptop · SQLite backend, pool size 8 ·
3,200 requests per run · clients in their own processes.

| Concurrent clients | Throughput | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- |
| 1 | 1,847 req/s | 0.47 ms | 0.58 ms | 0.72 ms | 8 ms |
| 8 | 1,756 req/s | 0.60 ms | 5.84 ms | 41.8 ms | 872 ms |
| 32 | 1,505 req/s | 7.42 ms | 17.4 ms | 72.8 ms | 1,007 ms |

Every run returned HTTP 200 for every request, and the audit hash chain verified
gapless afterwards.

## What limits it

**The ceiling is the audit chain write, not the connection pool.** One client is
the *fastest* configuration; adding clients lowers throughput slightly and costs
tail latency. That is the signature of a fully serialised bottleneck.

Every permit and every deny writes an audit row, and the chain's
head-read-then-insert must be atomic — so each write takes SQLite's write
reservation via `BEGIN IMMEDIATE`. Writes are therefore single-file no matter how
many connections exist. The pool adds contention overhead without adding
parallelism for the dominant cost.

This is worth stating plainly because 0.5.0's connection pool (#150) is easy to
read as a throughput win. It isn't one. What it removed was a process-global lock
that covered the *entire request* — parsing, auth lookups, response writing — so
those now overlap, and a slow request no longer blocks unrelated ones. The
request/second ceiling was never the lock; it was, and still is, the serialised
chain write.

The same structure exists on Postgres, where every audit write takes one global
advisory lock — so this ceiling is a property of the design, not of SQLite.
Raising it means changing how the chain is written (batching, per-workspace
chains, or decoupling the durable write from the response), which is a design
question rather than a tuning one.

Tail latency does grow with concurrency (p99 0.7 ms → 73 ms from 1 to 32
clients, with a ~1 s worst case). Clients queue for the write reservation, and
the busy timeout is what keeps them waiting rather than failing.

## Method, and one trap

`tools/loadtest.py` runs its clients in **separate processes**, deliberately.

The service is a threaded Python server, so its worker threads already share one
GIL — that is the product's real behaviour and belongs in the number. But a load
generator running *in the same process* contends for that same GIL and gets
counted as server latency. An early version of this script did exactly that and
reported throughput collapsing 3.4× past 8 clients. That collapse was the harness
measuring itself; with clients moved out of process it disappeared entirely and
the curve went flat.

If you write another load tool for this service, put the load somewhere the GIL
isn't.

## Why this is not a CI gate

Shared CI runners cannot produce stable throughput numbers, and a perf gate that
flakes is one everyone learns to ignore within a week. Correctness under load
*is* gated — `tests/test_local_http_concurrency.py` hammers a real service and
asserts no drops, no 5xx, no lock errors. This document and the tool are for
deliberate comparison: run it on a machine you control, against two revisions,
and read the difference.
