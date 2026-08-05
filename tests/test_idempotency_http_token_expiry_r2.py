from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from idempotency_http_fixtures import AGENT_HEADERS
from idempotency_http_memory_transport import post_memory_raw_json
from idempotency_sqlite_http_scenarios import (
    configured_sqlite_service,
    persisted_counts,
    seed_success_routes,
    set_database_epoch,
)

import vinctor_service.subject_tokens
from vinctor_core import Grant


@dataclass(frozen=True, slots=True)
class _TokenExpiryCase:
    label: str
    request_now: datetime
    database_now_epoch: int
    ttl_seconds: int
    expected_source: str


_TOKEN_EXPIRY_CASES = (
    _TokenExpiryCase(
        label="authoritative-token-cap-process-past",
        request_now=datetime(2001, 1, 1, tzinfo=UTC),
        database_now_epoch=int(datetime(2001, 1, 1, tzinfo=UTC).timestamp()),
        ttl_seconds=60,
        expected_source="token",
    ),
    _TokenExpiryCase(
        label="terminal-ttl-cap-process-future",
        request_now=datetime(2100, 1, 1, tzinfo=UTC),
        database_now_epoch=int(datetime(2100, 1, 1, tzinfo=UTC).timestamp()),
        ttl_seconds=172_800,
        expected_source="terminal_ttl",
    ),
)


@pytest.mark.parametrize("case", _TOKEN_EXPIRY_CASES, ids=lambda case: case.label)
def test_token_restart_expiry_uses_db_time_and_authoritative_result(
    case: _TokenExpiryCase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_property: Callable[[str, object], None],
) -> None:
    database = tmp_path / f"{case.label}.sqlite3"
    monkeypatch.setenv(
        "VINCTOR_SUBJECT_TOKEN_MAX_TTL_SECONDS",
        str(case.ttl_seconds),
    )
    service, connection = configured_sqlite_service(database)
    seed_success_routes(service)
    service.insert_grant(
        Grant(
            grant_id=f"grnt_{case.label}",
            grant_ref=f"grt_{case.label}",
            workspace_id="ws_main",
            agent_id="agent_release",
            scopes=("write:repo/feature/*",),
            status="active",
            expires_at=case.request_now + timedelta(seconds=case.ttl_seconds + 3_600),
        )
    )
    set_database_epoch(connection, case.database_now_epoch)
    request_body = (
        b'{"grant_ref":"grt_'
        + case.label.encode("ascii")
        + b'","audience":"pep_main","ttl_seconds":'
        + str(case.ttl_seconds).encode("ascii")
        + b"}"
    )
    headers = (*tuple(AGENT_HEADERS.items()), ("Idempotency-Key", f"expiry-{case.label}"))
    before = persisted_counts(connection)
    first = post_memory_raw_json(
        service,
        "/v1/tokens",
        request_body,
        headers,
        request_now=case.request_now,
    )
    after_first = persisted_counts(connection)
    first_row = connection.execute(
        "SELECT expires_at_epoch FROM idempotency_results WHERE operation = 'subject_token.mint.v1'"
    ).fetchone()
    connection.close()

    restarted_service, restarted_connection = configured_sqlite_service(database)
    set_database_epoch(restarted_connection, case.database_now_epoch)
    replay = post_memory_raw_json(
        restarted_service,
        "/v1/tokens",
        request_body,
        headers,
        request_now=case.request_now,
    )
    after_replay = persisted_counts(restarted_connection)
    replay_row = restarted_connection.execute(
        "SELECT expires_at_epoch FROM idempotency_results WHERE operation = 'subject_token.mint.v1'"
    ).fetchone()
    restarted_connection.close()

    token_expiry_epoch = int((case.request_now + timedelta(seconds=case.ttl_seconds)).timestamp())
    terminal_expiry_epoch = case.database_now_epoch + 86_400
    expected_expiry_epoch = min(terminal_expiry_epoch, token_expiry_epoch)
    assert case.expected_source == (
        "token" if token_expiry_epoch <= terminal_expiry_epoch else "terminal_ttl"
    )
    assert first.status_code == 201
    assert replay == first
    assert first_row == (expected_expiry_epoch,)
    assert replay_row == first_row
    assert after_first.tokens == before.tokens + 1
    assert after_first.audits == before.audits + 1
    assert after_first.results == before.results + 1
    assert after_replay == after_first
    record_property("expiry_source", case.expected_source)
    record_property("database_now_epoch", case.database_now_epoch)
    record_property("token_expiry_epoch", token_expiry_epoch)
    record_property("terminal_expiry_epoch", terminal_expiry_epoch)
    record_property("persisted_expiry_epoch", expected_expiry_epoch)
    record_property("replay_bytes_equal", replay == first)
    record_property("tokens_after_replay", after_replay.tokens)
    record_property("results_after_replay", after_replay.results)


def test_token_expiry_at_db_time_is_not_replayable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_property: Callable[[str, object], None],
) -> None:
    request_now = datetime(2001, 1, 1, tzinfo=UTC)
    token_expiry_epoch = int((request_now + timedelta(seconds=60)).timestamp())
    generated = {
        "vat_": iter(("vat_first", "vat_second")),
        "vtk_": iter(("vtk_first", "vtk_second")),
    }
    monkeypatch.setattr(
        vinctor_service.subject_tokens,
        "_new_key",
        lambda prefix: next(generated[prefix]),
    )
    database = tmp_path / "strict-no-grace.sqlite3"
    service, connection = configured_sqlite_service(database)
    service.insert_grant(
        Grant(
            grant_id="grnt_strict_expiry",
            grant_ref="grt_strict_expiry",
            workspace_id="ws_main",
            agent_id="agent_release",
            scopes=("write:repo/feature/*",),
            status="active",
            expires_at=request_now + timedelta(hours=1),
        )
    )
    set_database_epoch(connection, token_expiry_epoch)
    request_body = b'{"grant_ref":"grt_strict_expiry","audience":"pep_main","ttl_seconds":60}'
    headers = (*tuple(AGENT_HEADERS.items()), ("Idempotency-Key", "strict-no-grace"))
    before = persisted_counts(connection)
    first = post_memory_raw_json(
        service,
        "/v1/tokens",
        request_body,
        headers,
        request_now=request_now,
    )
    after_first = persisted_counts(connection)
    first_row = connection.execute(
        "SELECT expires_at_epoch FROM idempotency_results WHERE operation = 'subject_token.mint.v1'"
    ).fetchone()
    connection.close()

    restarted_service, restarted_connection = configured_sqlite_service(database)
    set_database_epoch(restarted_connection, token_expiry_epoch)
    second = post_memory_raw_json(
        restarted_service,
        "/v1/tokens",
        request_body,
        headers,
        request_now=request_now,
    )
    after_second = persisted_counts(restarted_connection)
    second_row = restarted_connection.execute(
        "SELECT expires_at_epoch FROM idempotency_results WHERE operation = 'subject_token.mint.v1'"
    ).fetchone()
    restarted_connection.close()

    assert first.body == (
        b'{"expires_at": "2001-01-01T00:01:00+00:00", '
        b'"token": "vat_first", "token_id": "vtk_first"}'
    )
    assert second.body == (
        b'{"expires_at": "2001-01-01T00:01:00+00:00", '
        b'"token": "vat_second", "token_id": "vtk_second"}'
    )
    assert first_row is None
    assert second_row is None
    assert after_first.tokens == before.tokens + 1
    assert after_first.audits == before.audits + 1
    assert after_first.results == before.results
    assert after_second.tokens == after_first.tokens + 1
    assert after_second.audits == after_first.audits + 1
    assert after_second.results == after_first.results
    assert after_second.reservations == after_first.reservations + 1
    record_property("database_now_epoch", token_expiry_epoch)
    record_property("first_result_row_present", first_row is not None)
    record_property("second_result_row_present", second_row is not None)
    record_property("first_and_second_bytes_equal", first == second)
    record_property("tokens_after_second", after_second.tokens)
    record_property("results_after_second", after_second.results)
