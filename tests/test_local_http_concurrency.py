"""Concurrency regression for the pooled-SQLite local HTTP service.

Each worker leases one connection/service for its whole request. This test
hammers a real SQLite-backed service from many threads and asserts every request
gets a clean permit — no drops, no database-lock errors, and no 5xx.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Thread

from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service

WORKERS = 8
TOTAL_REQUESTS = 600


def _enforce_once(endpoint: str, agent_key: str, grant_ref: str) -> int | str:
    body = json.dumps(
        {"grant_ref": grant_ref, "action": "read", "resource": "test/data/file"}
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{endpoint}/v1/enforce",
        data=body,
        headers={"Content-Type": "application/json", "X-Agent-Key": agent_key},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}"
    except Exception as e:  # RemoteDisconnected etc.
        return f"ERR {type(e).__name__}"


def test_concurrent_enforce_never_drops_a_connection(tmp_path: Path) -> None:
    handle = prepare_local_service(
        LocalLaunchConfig(
            db_path=tmp_path / "conc.sqlite",
            port=0,
            scopes=("read:test/data/*",),
        )
    )
    assert handle.sqlite_pool is not None
    assert handle.sqlite_pool.size >= WORKERS
    thread = Thread(target=handle.server.serve_forever, daemon=True)
    thread.start()
    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = list(
                pool.map(
                    lambda _: _enforce_once(handle.endpoint, handle.agent_key, handle.grant_ref),
                    range(TOTAL_REQUESTS),
                )
            )
    finally:
        handle.server.shutdown()
        thread.join(timeout=5)
        handle.close()

    # Every concurrent request must get a clean 200 permit: no dropped
    # connections (ERR RemoteDisconnected), no SQLite-induced 5xx.
    non_200 = [r for r in results if r != 200]
    assert non_200 == [], f"{len(non_200)}/{TOTAL_REQUESTS} requests were not 200: {non_200[:5]}"
