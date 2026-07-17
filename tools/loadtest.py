#!/usr/bin/env python3
"""Measure throughput and latency against a real local service.

It is a **measurement tool, not a CI gate**. Shared CI runners cannot give
stable throughput figures, and a perf gate that flakes is a perf gate everyone
learns to ignore inside a week. Run it on a machine you control, record the
result, and compare deliberately. Correctness under load already has a real gate
in tests/test_local_http_concurrency.py.

One invocation measures one configuration ("cell"). The levers exist so that a
flat curve can be *attributed* instead of narrated:

  * --endpoint enforce|readyz|healthz is a cost ladder. /healthz answers from
    process state (no pooled connection, no database), /readyz leases a pooled
    connection for SELECT 1, /v1/enforce does auth + decision + audit write.
    The throughput deltas between rungs attribute the cost.
  * --keepalive reuses one TCP connection per worker. The shipped handler
    speaks HTTP/1.0 and closes the connection after every response, so this
    mode also flips the handler class to HTTP/1.1 for the run — a DIAGNOSTIC
    configuration, not the shipped server. It exists to price connection churn.
  * --pool-size varies the SQLite service pool. prepare_local_service does not
    expose the pool's `size` argument, so the harness substitutes a
    size-pinning wrapper for local_launcher.SQLiteServicePool during setup and
    verifies handle.sqlite_pool.size afterwards (no library code is changed).

Measurement protocol, because the previous version of this tool timed its own
scaffolding: worker processes are created with an explicit spawn context, pay
their imports, open their connections and run their warmup BEFORE a barrier;
the clock starts when the parent passes that barrier and stops when the last
worker reports its final response complete (a tiny done-token on its own
queue; bulky latency payloads travel on a second queue after the clock stops).
Spawn cost is reported separately as setup_seconds. Latencies are per-request
perf_counter deltas inside each worker — durations, never cross-process clock
comparisons — and cover exactly the requests inside the timed window.

Each repetition uses a fresh database and server. The run fails (nonzero exit)
if any request came back non-200, if the audit chain does not verify, or — on
a clean enforce run — if the audit row count is not exactly baseline + warmup
+ measured. The last check exists because verify_chain cannot see a
self-consistent tail loss: a chain whose last k rows vanished still verifies.

Usage:

    python tools/loadtest.py                             # 8 workers, 2000 requests
    python tools/loadtest.py --workers 32 --requests 10000 --repeat 5
    python tools/loadtest.py --endpoint healthz --json   # transport-only control
"""

from __future__ import annotations

import argparse
import functools
import http.client
import json
import multiprocessing
import os
import platform
import queue
import resource
import statistics
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from threading import BrokenBarrierError, Thread

# method, path per endpoint rung. See the module docstring for what each rung pays.
_ENDPOINTS = {
    "enforce": ("POST", "/v1/enforce"),
    "readyz": ("GET", "/readyz"),
    "healthz": ("GET", "/healthz"),
}

_STARTUP_TIMEOUT_SECONDS = 60
_RESULT_TIMEOUT_SECONDS = 300


class _CountingConnection(http.client.HTTPConnection):
    """HTTPConnection that counts real TCP connects.

    http.client transparently reconnects a closed connection on the next
    request (auto_open), so "I passed --keepalive" says nothing about whether
    reuse actually happened. The connect count does: ~1 per worker means reuse,
    ~1 per request means the server closed on us anyway.
    """

    connect_count = 0

    def connect(self) -> None:
        self.connect_count += 1
        super().connect()


def _request_once(
    conn: _CountingConnection,
    method: str,
    path: str,
    body: bytes | None,
    headers: dict[str, str],
    keepalive: bool,
) -> tuple[str, float]:
    """One request. Returns (outcome, seconds). Connect cost, when a connect
    happens, is inside the timing — that is the cost a real caller pays."""
    started = time.perf_counter()
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        response.read()
        outcome = "200" if response.status == 200 else f"HTTP {response.status}"
    except Exception as exc:  # RemoteDisconnected, timeouts, resets
        outcome = type(exc).__name__
        conn.close()  # reset so the next request reconnects cleanly
    else:
        if not keepalive:
            conn.close()
    return outcome, time.perf_counter() - started


def _worker_main(worker_id, cfg, barrier, done_queue, results_queue) -> None:
    """One load-generating client, in its own spawned process.

    Separate processes on purpose: the service is a threaded Python server, so
    its worker threads already contend for one GIL — that is the product's real
    behaviour and belongs in the measurement. A load generator running in the
    same process would contend for that same GIL and get counted as if it were
    server latency; an early version of this harness did exactly that and
    reported throughput collapsing past 8 clients, which was the harness
    measuring itself.

    Everything expensive (interpreter start, imports, TCP setup, warmup)
    happens before the barrier. After the barrier: requests only, then the
    done-token, then the bulky results.
    """
    try:
        conn = _CountingConnection(cfg["host"], cfg["port"], timeout=30)
        for _ in range(cfg["warmup"]):
            _request_once(
                conn, cfg["method"], cfg["path"], cfg["body"], cfg["headers"], cfg["keepalive"]
            )
    except BaseException as exc:
        barrier.abort()  # unblock the parent immediately
        results_queue.put({"worker": worker_id, "error": f"{type(exc).__name__}: {exc}"})
        return

    try:
        barrier.wait(timeout=_STARTUP_TIMEOUT_SECONDS)
    except BrokenBarrierError:
        results_queue.put({"worker": worker_id, "error": "startup barrier broken"})
        return

    error = None
    results: list[tuple[str, float]] = []
    usage_before = resource.getrusage(resource.RUSAGE_SELF)
    try:
        for _ in range(cfg["count"]):
            results.append(
                _request_once(
                    conn,
                    cfg["method"],
                    cfg["path"],
                    cfg["body"],
                    cfg["headers"],
                    cfg["keepalive"],
                )
            )
    except BaseException as exc:  # keep the parent's clock from hanging
        error = f"{type(exc).__name__}: {exc}"
    done_queue.put(worker_id)
    usage_after = resource.getrusage(resource.RUSAGE_SELF)
    results_queue.put(
        {
            "worker": worker_id,
            "error": error,
            "results": results,
            "cpu_seconds": (usage_after.ru_utime + usage_after.ru_stime)
            - (usage_before.ru_utime + usage_before.ru_stime),
            "tcp_connects": conn.connect_count,
        }
    )


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    index = min(int(len(values) * fraction), len(values) - 1)
    return sorted(values)[index]


def _split_requests(requests: int, workers: int) -> list[int]:
    """Exact split, remainder spread over the first workers. Nothing is rounded
    away: sum(counts) == requests, and an uneven split is reported as such."""
    base, extra = divmod(requests, workers)
    return [base + 1] * extra + [base] * (workers - extra)


def _verify_chain(db_path: Path) -> dict[str, object]:
    from vinctor_service.sqlite import SQLiteV1Service
    from vinctor_service.sqlite_txn import connect_sqlite

    conn = connect_sqlite(db_path)
    try:
        service = SQLiteV1Service(conn, initialize_schema=False)
        result = service.audit_writer.verify_chain()
        return {"ok": result.ok, "count": result.count, "head_seq": result.head_seq}
    finally:
        conn.close()


def _prepare_handle(db_path: Path, pool_size: int | None):
    """Build the service exactly as `vinctor local start` does, optionally
    pinning the SQLite pool size (see the module docstring for why this is a
    wrapper substitution and not a config option)."""
    # Lazy imports: worker processes re-import this module under spawn and
    # must not pay for the whole vinctor_service package.
    import vinctor_service.local_launcher as local_launcher

    config = local_launcher.LocalLaunchConfig(db_path=db_path, port=0, scopes=("read:test/*",))
    if pool_size is None:
        return local_launcher.prepare_local_service(config)

    original = local_launcher.SQLiteServicePool
    local_launcher.SQLiteServicePool = functools.partial(original, size=pool_size)
    try:
        handle = local_launcher.prepare_local_service(config)
    finally:
        local_launcher.SQLiteServicePool = original
    if handle.sqlite_pool is None or handle.sqlite_pool.size != pool_size:
        handle.close()
        raise RuntimeError(
            f"pool size pin did not take (wanted {pool_size}, "
            f"got {handle.sqlite_pool.size if handle.sqlite_pool else None})"
        )
    return handle


def _run_once(
    db_path: Path,
    *,
    endpoint: str,
    per_worker: list[int],
    warmup: int,
    keepalive: bool,
    pool_size: int | None,
) -> dict[str, object]:
    method, path = _ENDPOINTS[endpoint]
    workers = len(per_worker)
    measured_total = sum(per_worker)

    handle = _prepare_handle(db_path, pool_size)
    actual_pool_size = handle.sqlite_pool.size if handle.sqlite_pool else None
    thread = None
    try:
        # Baseline BEFORE any load: bootstrap itself writes audit rows.
        baseline_rows = int(_verify_chain(db_path)["count"])  # type: ignore[arg-type]

        if keepalive:
            # Diagnostic mode: the shipped handler is HTTP/1.0 and closes every
            # connection, so client-side keep-alive alone is a no-op. Flip this
            # server instance (the handler class is per-server) to HTTP/1.1.
            handle.server.RequestHandlerClass.protocol_version = "HTTP/1.1"

        thread = Thread(target=handle.server.serve_forever, daemon=True)
        thread.start()

        host, port = handle.server.server_address[0], handle.server.server_address[1]
        headers = {}
        body = None
        if endpoint == "enforce":
            body = json.dumps(
                {"grant_ref": handle.grant_ref, "action": "read", "resource": "test/file"}
            ).encode("utf-8")
            headers = {"Content-Type": "application/json", "X-Agent-Key": handle.agent_key}
        if not keepalive:
            headers["Connection"] = "close"

        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(workers + 1)
        done_queue = ctx.Queue()
        results_queue = ctx.Queue()
        processes = []
        setup_started = time.perf_counter()
        try:
            for worker_id, count in enumerate(per_worker):
                cfg = {
                    "host": host,
                    "port": port,
                    "method": method,
                    "path": path,
                    "body": body,
                    "headers": headers,
                    "warmup": warmup,
                    "count": count,
                    "keepalive": keepalive,
                }
                process = ctx.Process(
                    target=_worker_main,
                    args=(worker_id, cfg, barrier, done_queue, results_queue),
                )
                process.start()
                processes.append(process)

            try:
                barrier.wait(timeout=_STARTUP_TIMEOUT_SECONDS)
            except BrokenBarrierError:
                errors = []
                try:
                    while True:
                        payload = results_queue.get(timeout=1)
                        if payload.get("error"):
                            errors.append(f"worker {payload['worker']}: {payload['error']}")
                except queue.Empty:
                    pass
                raise RuntimeError(
                    "a worker failed before the measured window: "
                    + ("; ".join(errors) if errors else "no error reported")
                ) from None

            # ---- timed window: requests only -------------------------------
            started = time.perf_counter()
            server_usage_before = resource.getrusage(resource.RUSAGE_SELF)
            try:
                for _ in range(workers):
                    done_queue.get(timeout=_RESULT_TIMEOUT_SECONDS)
            except queue.Empty:
                raise RuntimeError(
                    "a worker never reported completion inside "
                    f"{_RESULT_TIMEOUT_SECONDS}s; the window cannot be closed honestly"
                ) from None
            elapsed = time.perf_counter() - started
            server_usage_after = resource.getrusage(resource.RUSAGE_SELF)
            # ---- window closed ----------------------------------------------

            setup_seconds = started - setup_started
            payloads = [
                results_queue.get(timeout=_RESULT_TIMEOUT_SECONDS) for _ in range(workers)
            ]
            for process in processes:
                process.join(timeout=30)
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()

        worker_errors = [p["error"] for p in payloads if p.get("error")]
        results = [item for p in payloads for item in p.get("results", [])]
        outcomes = Counter(outcome for outcome, _ in results)
        latencies = [seconds for _, seconds in results]
        tcp_connects = sum(p.get("tcp_connects", 0) for p in payloads)
        client_cpu = sum(p.get("cpu_seconds", 0.0) for p in payloads)
        server_cpu = (server_usage_after.ru_utime + server_usage_after.ru_stime) - (
            server_usage_before.ru_utime + server_usage_before.ru_stime
        )
    finally:
        # shutdown() blocks on an event that only serve_forever() sets, so it
        # must not run when the server thread never started.
        if thread is not None:
            handle.server.shutdown()
            thread.join(timeout=5)
        handle.close()

    chain = _verify_chain(db_path)
    clean = outcomes.get("200", 0) == measured_total and not worker_errors

    # Exact row accounting, only assertable when every request permitted:
    # each 200 enforce (warmup included) writes exactly one audit row; the
    # database-free endpoints write none.
    expected_rows = baseline_rows + (
        (warmup * workers + measured_total) if endpoint == "enforce" else 0
    )
    rows_exact = None
    if clean:
        rows_exact = chain["count"] == expected_rows

    # The lever must be shown to have worked, not assumed. With keep-alive,
    # connects should be ~1 per worker; without, one per request (warmup too).
    if keepalive:
        connections_verified = tcp_connects <= 2 * workers
    else:
        connections_verified = tcp_connects >= warmup * workers + measured_total

    return {
        "window_seconds": round(elapsed, 4),
        "setup_seconds": round(setup_seconds, 3),
        "throughput_rps": round(measured_total / elapsed, 1) if elapsed else 0.0,
        "outcomes": dict(outcomes),
        "clean": clean,
        "worker_errors": worker_errors,
        "tcp_connects": tcp_connects,
        "connections_verified": connections_verified,
        "server_cpu_cores": round(server_cpu / elapsed, 2) if elapsed else 0.0,
        "client_cpu_cores": round(client_cpu / elapsed, 2) if elapsed else 0.0,
        "pool_size": actual_pool_size,
        "latency_ms": {
            "p50": round(_percentile(latencies, 0.50) * 1000, 2),
            "p95": round(_percentile(latencies, 0.95) * 1000, 2),
            "p99": round(_percentile(latencies, 0.99) * 1000, 2),
            "max": round(max(latencies) * 1000, 2) if latencies else 0.0,
            "mean": round(statistics.fmean(latencies) * 1000, 2) if latencies else 0.0,
        },
        "audit_chain": {
            **chain,
            "baseline_rows": baseline_rows,
            "expected_rows": expected_rows if clean else None,
            "rows_exact": rows_exact,
        },
        "ok": bool(clean and chain["ok"] and rows_exact is not False and connections_verified),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--workers", type=int, default=8, help="client processes (>= 1)")
    parser.add_argument("--requests", type=int, default=2000, help="total measured requests")
    parser.add_argument(
        "--warmup", type=int, default=10, help="uncounted warmup requests per worker"
    )
    parser.add_argument(
        "--repeat", type=int, default=1, help="repetitions, each with a fresh server and database"
    )
    parser.add_argument("--endpoint", choices=sorted(_ENDPOINTS), default="enforce")
    parser.add_argument(
        "--keepalive",
        action="store_true",
        help="reuse one TCP connection per worker (flips the server to HTTP/1.1 "
        "for the run — a diagnostic, not the shipped configuration)",
    )
    parser.add_argument(
        "--pool-size", type=int, default=None, help="SQLite service pool size (default: library's)"
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.requests < args.workers:
        parser.error("--requests must be at least --workers (every worker sends >= 1 request)")
    if args.warmup < 0:
        parser.error("--warmup must not be negative")
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    if args.pool_size is not None and args.pool_size < 1:
        parser.error("--pool-size must be at least 1")

    per_worker = _split_requests(args.requests, args.workers)
    method, path = _ENDPOINTS[args.endpoint]

    reps = []
    for _ in range(args.repeat):
        with tempfile.TemporaryDirectory() as tmp:
            reps.append(
                _run_once(
                    Path(tmp) / "loadtest.sqlite",
                    endpoint=args.endpoint,
                    per_worker=per_worker,
                    warmup=args.warmup,
                    keepalive=args.keepalive,
                    pool_size=args.pool_size,
                )
            )

    throughputs = sorted(rep["throughput_rps"] for rep in reps)
    report = {
        "endpoint": path,
        "method": method,
        "workers": args.workers,
        "requests": sum(per_worker),
        "per_worker_requests": dict(Counter(per_worker)),
        "warmup_per_worker": args.warmup,
        "keepalive": args.keepalive,
        "pool_size": reps[0]["pool_size"],
        "machine": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "throughput_rps": {
            "median": round(statistics.median(throughputs), 1),
            "min": throughputs[0],
            "max": throughputs[-1],
        },
        "reps": reps,
        "ok": all(rep["ok"] for rep in reps),
    }

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1

    split = report["per_worker_requests"]
    split_note = "" if len(split) == 1 else f"  (uneven split {split})"
    print(
        f"{method} {path}  workers={args.workers}  requests={report['requests']}"
        f"{split_note}  keepalive={'on' if args.keepalive else 'off'}"
        f"  pool={report['pool_size']}"
    )
    for index, rep in enumerate(reps, start=1):
        latency = rep["latency_ms"]
        print(
            f"rep {index}: {rep['throughput_rps']:>7} req/s  window={rep['window_seconds']}s"
            f"  setup={rep['setup_seconds']}s  p50={latency['p50']}ms p99={latency['p99']}ms"
            f"  server_cpu={rep['server_cpu_cores']} cores  connects={rep['tcp_connects']}"
        )
    spread = report["throughput_rps"]
    print(
        f"throughput   median {spread['median']} req/s  "
        f"(min {spread['min']}, max {spread['max']}, n={args.repeat})"
    )
    chain = reps[-1]["audit_chain"]
    print(
        f"audit chain  ok={chain['ok']}  rows={chain['count']}"
        f"  expected={chain['expected_rows']}  rows_exact={chain['rows_exact']}"
    )

    if not report["ok"]:
        failures = []
        for index, rep in enumerate(reps, start=1):
            if not rep["clean"]:
                failures.append(f"rep {index}: non-200 outcomes {rep['outcomes']}"
                                + (f", worker errors {rep['worker_errors']}"
                                   if rep["worker_errors"] else ""))
            if not rep["audit_chain"]["ok"]:
                failures.append(f"rep {index}: audit chain broken")
            if rep["audit_chain"]["rows_exact"] is False:
                failures.append(
                    f"rep {index}: audit rows {rep['audit_chain']['count']} != expected "
                    f"{rep['audit_chain']['expected_rows']} (possible tail loss)"
                )
            if not rep["connections_verified"]:
                failures.append(
                    f"rep {index}: tcp_connects={rep['tcp_connects']} inconsistent with "
                    f"keepalive={'on' if args.keepalive else 'off'} — the lever did not "
                    "do what the flag claims, so the number does not measure it"
                )
        print("\nNOT OK:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
