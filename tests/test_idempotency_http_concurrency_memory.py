from __future__ import annotations

from datetime import datetime
from pathlib import Path
from threading import Barrier, Lock, Thread

import pytest
from idempotency_http_fixtures import RawResponse
from idempotency_http_header_scenarios import VALID_GRANT_BODY
from idempotency_http_memory_transport import post_memory_raw_json
from idempotency_sqlite_http_scenarios import (
    configured_sqlite_service,
    persisted_counts,
    seed_success_routes,
)

from vinctor_service.idempotency_models import (
    IdempotencyInvocation,
    IdempotencyMutation,
    PreSerializedHttpResponse,
)
from vinctor_service.models import GrantIssueRequest, GrantIssueResult
from vinctor_service.sqlite import SQLiteV1Service


def test_same_key_concurrent_handler_requests_share_one_terminal_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, connection = configured_sqlite_service(
        tmp_path / "concurrent.sqlite3",
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

    def request(index: int) -> None:
        try:
            responses[index] = post_memory_raw_json(
                service,
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
