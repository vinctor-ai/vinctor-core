#!/usr/bin/env python3
"""Measure enforce throughput and latency against a real local service.

The concurrency ceiling has been known but unquantified. #150 replaced the
process-global request lock with a bounded connection pool, and the changelog
says parsing, auth lookups and response writing now run in parallel — but no
number was ever produced, so "the ceiling moved" stayed a claim. This produces
the number.

It is a **measurement tool, not a CI gate**. Shared CI runners cannot give
stable throughput figures, and a perf gate that flakes is a perf gate everyone
learns to ignore inside a week. Run it on a machine you control, record the
result, and compare deliberately. Correctness under load already has a real gate
in tests/test_local_http_concurrency.py.

What it reports:

  * throughput (requests/second across the whole run)
  * latency percentiles, which is where a connection pool actually shows up —
    the mean hides the queueing this is meant to expose
  * an error taxonomy rather than a count, because "12 errors" and "12 dropped
    connections" mean very different things
  * whether the audit hash chain is still gapless afterwards, since every permit
    writes an audit row and serialised chain writes are the real bottleneck

Usage:

    python tools/loadtest.py                       # 8 workers, 2000 requests
    python tools/loadtest.py --workers 32 --requests 10000
    python tools/loadtest.py --json                # machine-readable
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path
from threading import Thread

from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service

WARMUP_REQUESTS = 50


def _enforce_once(endpoint: str, agent_key: str, grant_ref: str) -> tuple[str, float]:
    """One enforce call. Returns (outcome, seconds)."""
    body = json.dumps(
        {"grant_ref": grant_ref, "action": "read", "resource": "test/file"}
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{endpoint}/v1/enforce",
        data=body,
        headers={"Content-Type": "application/json", "X-Agent-Key": agent_key},
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()
            outcome = "200" if response.status == 200 else f"HTTP {response.status}"
    except urllib.error.HTTPError as exc:
        outcome = f"HTTP {exc.code}"
    except Exception as exc:  # RemoteDisconnected, timeouts, resets
        outcome = f"{type(exc).__name__}"
    return outcome, time.perf_counter() - started


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    index = min(int(len(values) * fraction), len(values) - 1)
    return sorted(values)[index]


def _client_batch(args: tuple[str, str, str, int]) -> list[tuple[str, float]]:
    """One client, in its own process. Runs its share of the requests serially.

    This runs in a separate process on purpose. The service is a threaded Python
    server, so its worker threads already contend for one GIL — that is the
    product's real behaviour and belongs in the measurement. A load generator
    running *in the same process* would contend for that same GIL and get
    counted as if it were server latency: an early version of this script did
    exactly that and reported throughput collapsing past 8 clients, which was
    the harness measuring itself. Clients live in their own processes so the
    number describes the server.
    """
    endpoint, agent_key, grant_ref, count = args
    return [_enforce_once(endpoint, agent_key, grant_ref) for _ in range(count)]


def _run(workers: int, requests: int, db_path: Path) -> dict[str, object]:
    handle = prepare_local_service(
        LocalLaunchConfig(db_path=db_path, port=0, scopes=("read:test/*",))
    )
    thread = Thread(target=handle.server.serve_forever, daemon=True)
    thread.start()
    try:
        # Warm up in-process: this is about paying import/connection costs once,
        # not about measuring, so GIL sharing does not matter here.
        with ThreadPoolExecutor(max_workers=min(workers, 8)) as pool:
            list(pool.map(
                lambda _: _enforce_once(handle.endpoint, handle.agent_key, handle.grant_ref),
                range(WARMUP_REQUESTS),
            ))

        per_client = max(1, requests // workers)
        actual = per_client * workers
        batch = (handle.endpoint, handle.agent_key, handle.grant_ref, per_client)

        started = time.perf_counter()
        with ProcessPoolExecutor(max_workers=workers) as pool:
            batches = list(pool.map(_client_batch, [batch] * workers))
        elapsed = time.perf_counter() - started

        results = [item for group in batches for item in group]
        outcomes = Counter(outcome for outcome, _ in results)
        latencies = [seconds for _, seconds in results]
        pool_size = handle.sqlite_pool.size if handle.sqlite_pool else None
        requests = actual
    finally:
        handle.server.shutdown()
        thread.join(timeout=5)
        handle.close()

    return {
        "workers": workers,
        "requests": requests,
        "pool_size": pool_size,
        "seconds": round(elapsed, 3),
        "throughput_rps": round(requests / elapsed, 1) if elapsed else 0.0,
        "outcomes": dict(outcomes),
        "clean": outcomes.get("200", 0) == requests,
        "latency_ms": {
            "p50": round(_percentile(latencies, 0.50) * 1000, 2),
            "p95": round(_percentile(latencies, 0.95) * 1000, 2),
            "p99": round(_percentile(latencies, 0.99) * 1000, 2),
            "max": round(max(latencies) * 1000, 2) if latencies else 0.0,
            "mean": round(statistics.fmean(latencies) * 1000, 2) if latencies else 0.0,
        },
    }


def _verify_chain(db_path: Path) -> dict[str, object]:
    """Every permit writes an audit row; confirm the chain survived the load."""
    from vinctor_service.sqlite import SQLiteV1Service
    from vinctor_service.sqlite_txn import connect_sqlite

    conn = connect_sqlite(db_path)
    try:
        service = SQLiteV1Service(conn, initialize_schema=False)
        result = service.audit_writer.verify_chain()
        return {"ok": result.ok, "count": result.count, "head_seq": result.head_seq}
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "loadtest.sqlite"
        report = _run(args.workers, args.requests, db_path)
        try:
            report["audit_chain"] = _verify_chain(db_path)
        except Exception as exc:  # noqa: BLE001 - the report is the product
            report["audit_chain"] = {"error": f"{type(exc).__name__}: {exc}"}

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report["clean"] else 1

    latency = report["latency_ms"]
    chain = report["audit_chain"]
    print(f"workers={report['workers']}  requests={report['requests']}  "
          f"pool={report['pool_size']}  {report['seconds']}s")
    print(f"throughput   {report['throughput_rps']} req/s")
    print(f"latency ms   p50 {latency['p50']}  p95 {latency['p95']}  "
          f"p99 {latency['p99']}  max {latency['max']}")
    print(f"outcomes     {report['outcomes']}")
    if isinstance(chain, dict) and "ok" in chain:
        print(f"audit chain  ok={chain['ok']}  rows={chain['count']}  "
              f"head_seq={chain['head_seq']}")
    else:
        print(f"audit chain  {chain}")

    if not report["clean"]:
        print("\nNOT CLEAN — some requests did not return 200. The taxonomy above "
              "is the finding; a dropped connection is not a slow request.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
