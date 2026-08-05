from __future__ import annotations

import base64
from datetime import datetime
from threading import Barrier, Lock, Thread

import pytest
from idempotency_http_fixtures import NOW, RawResponse
from idempotency_http_header_scenarios import VALID_GRANT_BODY
from idempotency_http_memory_transport import post_memory_raw_json
from idempotency_postgres_fixtures import count_rows

from vinctor_service.idempotency_keyring import load_idempotency_keyring
from vinctor_service.idempotency_models import (
    IdempotencyInvocation,
    IdempotencyMutation,
    PreSerializedHttpResponse,
)
from vinctor_service.models import GrantIssueRequest, GrantIssueResult
from vinctor_service.postgres import PostgresV1Service, connect_postgres


def test_postgres_same_key_concurrent_http_composition_runs_one_mutation(
    requires_postgres: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded_key = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{encoded_key}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    connection = connect_postgres(requires_postgres)
    service = PostgresV1Service(connection, idempotency_keyring=keyring)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )
    before = (
        count_rows(connection, "grants"),
        count_rows(connection, "audit_events"),
        count_rows(connection, "idempotency_results"),
        count_rows(connection, "idempotency_cipher_nonces"),
    )
    connection.rollback()
    rendezvous = Barrier(2)
    mutation_lock = Lock()
    mutation_calls = 0
    original_execute = PostgresV1Service.execute_idempotent
    original_issue = PostgresV1Service.issue_grant

    def rendezvous_execute(
        self: PostgresV1Service,
        invocation: IdempotencyInvocation,
        mutation: IdempotencyMutation,
    ) -> PreSerializedHttpResponse:
        rendezvous.wait(timeout=5)
        return original_execute(self, invocation, mutation)

    def counted_issue(
        self: PostgresV1Service,
        request: GrantIssueRequest,
        *,
        now: datetime,
    ) -> GrantIssueResult:
        nonlocal mutation_calls
        with mutation_lock:
            mutation_calls += 1
        return original_issue(self, request, now=now)

    monkeypatch.setattr(PostgresV1Service, "execute_idempotent", rendezvous_execute)
    monkeypatch.setattr(PostgresV1Service, "issue_grant", counted_issue)
    headers = (
        ("X-Workspace-Key", "workspace_key_main"),
        ("Idempotency-Key", "postgres-concurrent-key"),
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
        after = (
            count_rows(connection, "grants"),
            count_rows(connection, "audit_events"),
            count_rows(connection, "idempotency_results"),
            count_rows(connection, "idempotency_cipher_nonces"),
        )
        assert after == tuple(
            value + delta for value, delta in zip(before, (1, 1, 1, 2), strict=True)
        )
        operations = connection.execute(
            "SELECT DISTINCT operation FROM idempotency_results"
        ).fetchall()
        assert operations == [("grant.issue.v1",)]
    finally:
        connection.close()


def test_postgres_result_insert_failure_is_coarse_and_burns_nonce(
    requires_postgres: str,
) -> None:
    encoded_key = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{encoded_key}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    connection = connect_postgres(requires_postgres)
    service = PostgresV1Service(connection, idempotency_keyring=keyring)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )
    headers = (
        ("X-Workspace-Key", "workspace_key_main"),
        ("Idempotency-Key", "postgres-result-insert-fault"),
    )
    trigger = "vinctor_http_reject_idempotency_result"
    before = (
        count_rows(connection, "grants"),
        count_rows(connection, "audit_events"),
        count_rows(connection, "idempotency_results"),
        count_rows(connection, "idempotency_cipher_nonces"),
    )
    connection.rollback()
    try:
        with connection.transaction():
            connection.execute(
                f'CREATE FUNCTION "{trigger}"() RETURNS trigger '
                "LANGUAGE plpgsql AS $$ BEGIN "
                "RAISE EXCEPTION 'sensitive driver detail'; END; $$"
            )
            connection.execute(
                f'CREATE TRIGGER "{trigger}" BEFORE INSERT ON idempotency_results '
                f'FOR EACH ROW EXECUTE FUNCTION "{trigger}"()'
            )

        failed = post_memory_raw_json(
            service,
            "/v1/grants",
            VALID_GRANT_BODY,
            headers,
        )
        after_failure = (
            count_rows(connection, "grants"),
            count_rows(connection, "audit_events"),
            count_rows(connection, "idempotency_results"),
            count_rows(connection, "idempotency_cipher_nonces"),
        )
        first_nonce = connection.execute(
            "SELECT nonce FROM idempotency_cipher_nonces ORDER BY slot DESC LIMIT 1"
        ).fetchone()
        connection.rollback()
        with connection.transaction():
            connection.execute(f'DROP TRIGGER "{trigger}" ON idempotency_results')
            connection.execute(f'DROP FUNCTION "{trigger}"()')

        retried = post_memory_raw_json(
            service,
            "/v1/grants",
            VALID_GRANT_BODY,
            headers,
        )
        second_nonce = connection.execute(
            "SELECT nonce FROM idempotency_cipher_nonces ORDER BY slot DESC LIMIT 1"
        ).fetchone()
        connection.rollback()

        assert failed.status_code == 503
        assert failed.body == (
            b'{"error": "idempotency_unavailable", '
            b'"reason": "idempotency_unavailable"}'
        )
        assert b"sensitive driver detail" not in failed.body
        assert after_failure == (
            before[0],
            before[1],
            before[2],
            before[3] + 1,
        )
        assert retried.status_code == 201
        assert first_nonce is not None
        assert second_nonce is not None
        assert first_nonce != second_nonce
    finally:
        with connection.transaction():
            connection.execute(
                f'DROP TRIGGER IF EXISTS "{trigger}" ON idempotency_results'
            )
            connection.execute(f'DROP FUNCTION IF EXISTS "{trigger}"()')
        service.close()
        connection.close()
