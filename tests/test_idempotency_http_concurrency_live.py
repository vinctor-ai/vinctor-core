from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Barrier, Lock, Thread

import pytest
from idempotency_http_fixtures import RawResponse, post_raw_json, running_server
from idempotency_http_header_scenarios import VALID_GRANT_BODY
from idempotency_sqlite_http_scenarios import (
    configured_sqlite_service,
    persisted_counts,
    seed_success_routes,
)

from vinctor_service.idempotency_keyring import load_idempotency_keyring
from vinctor_service.idempotency_models import (
    IdempotencyInvocation,
    IdempotencyMutation,
    PreSerializedHttpResponse,
)
from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service
from vinctor_service.models import GrantIssueRequest, GrantIssueResult
from vinctor_service.sqlite import SQLiteV1Service

WORKERS = 8


def test_same_key_concurrent_real_http_requests_share_one_terminal_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, connection = configured_sqlite_service(
        tmp_path / "concurrent-live.sqlite3",
        database_epoch=None,
    )
    seed_success_routes(service)
    before = persisted_counts(connection)
    rendezvous = Barrier(2)
    mutation_lock = Lock()
    mutation_calls = 0
    original_execute = SQLiteV1Service.execute_idempotent
    original_issue = SQLiteV1Service.issue_grant

    def rendezvous_execute(
        self: SQLiteV1Service,
        invocation: IdempotencyInvocation,
        mutation: IdempotencyMutation,
    ) -> PreSerializedHttpResponse:
        rendezvous.wait(timeout=5)
        return original_execute(self, invocation, mutation)

    def counted_issue(
        self: SQLiteV1Service,
        request: GrantIssueRequest,
        *,
        now: datetime,
    ) -> GrantIssueResult:
        nonlocal mutation_calls
        with mutation_lock:
            mutation_calls += 1
        return original_issue(self, request, now=now)

    monkeypatch.setattr(SQLiteV1Service, "execute_idempotent", rendezvous_execute)
    monkeypatch.setattr(SQLiteV1Service, "issue_grant", counted_issue)
    headers = (
        ("X-Workspace-Key", "workspace_key_main"),
        ("Idempotency-Key", "concurrent-same-key"),
    )
    responses: list[RawResponse | None] = [None, None]
    failures: list[BaseException] = []

    with running_server(service) as server:

        def request(index: int) -> None:
            try:
                responses[index] = post_raw_json(
                    server,
                    "/v1/grants",
                    VALID_GRANT_BODY,
                    headers,
                )
            except BaseException as error:
                failures.append(error)

        threads = (Thread(target=request, args=(0,)), Thread(target=request, args=(1,)))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

    try:
        assert all(not thread.is_alive() for thread in threads)
        assert failures == []
        first, second = responses
        assert first is not None
        assert second is not None
        assert first == second
        assert first.status_code == 201
        assert mutation_calls == 1
        after = persisted_counts(connection)
        assert after.grants == before.grants + 1
        assert after.audits == before.audits + 1
        assert after.results == before.results + 1
        assert 1 <= after.reservations - before.reservations <= 2
    finally:
        connection.close()


def test_eight_same_key_requests_use_the_production_pool_without_starvation(
    tmp_path: Path,
) -> None:
    # Given the production local launcher with all eight pooled SQLite connections.
    encoded_key = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{encoded_key}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    handle = prepare_local_service(
        LocalLaunchConfig(
            db_path=tmp_path / "eight-worker.sqlite3",
            port=0,
            idempotency_keyring=keyring,
        )
    )
    assert handle.sqlite_pool is not None
    before = persisted_counts(handle.conn)
    server_thread = Thread(target=handle.server.serve_forever, daemon=True)
    server_thread.start()
    headers = (
        ("X-Workspace-Key", handle.workspace_key),
        ("Idempotency-Key", "eight-worker-key"),
    )
    body = (
        b'{"agent_id":"agent_local","scopes":["write:repo/feature/readme"],'
        b'"ttl_seconds":60}'
    )
    try:
        # When eight clients concurrently submit the exact same keyed mutation.
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futures = tuple(
                pool.submit(
                    post_raw_json,
                    handle.server,
                    "/v1/grants",
                    body,
                    headers,
                )
                for _ in range(WORKERS)
            )
            responses = tuple(future.result(timeout=15) for future in futures)

        # Then every request completes with one exact result and the pool remains healthy.
        after = persisted_counts(handle.conn)
        assert all(response == responses[0] for response in responses)
        assert responses[0].status_code == 201
        assert (
            after.grants - before.grants,
            after.audits - before.audits,
            after.results - before.results,
        ) == (1, 1, 1)
        assert 1 <= after.reservations - before.reservations <= WORKERS
        assert handle.sqlite_pool.capacity == WORKERS
        assert handle.sqlite_pool.is_ready() is True
    finally:
        handle.server.shutdown()
        server_thread.join(timeout=5)
        handle.close()
