from __future__ import annotations

import logging
from pathlib import Path

import pytest
from idempotency_http_fixtures import RawResponse
from idempotency_http_header_scenarios import (
    exercise_absent_keyring,
    exercise_header_lines,
    exercise_raw_key_redaction,
    exercise_validation_precedence,
)
from idempotency_http_replay_scenarios import (
    exercise_conflict,
    exercise_replay,
    exercise_scoped_operations,
    state_value,
)
from idempotency_http_terminal_case import RouteCase
from idempotency_http_terminal_expectations import (
    EXPECTED_TERMINAL_RESPONSES,
    assert_expected_terminal_response,
)
from idempotency_http_terminal_matrix import ROUTE_CASES


def _wire(response: RawResponse) -> tuple[int, str, int, bytes]:
    return (
        response.status_code,
        response.content_type,
        response.content_length,
        response.body,
    )


def test_duplicate_idempotency_header_is_uncached_400_before_mapping_collapse() -> None:
    # Given two raw retry-key field lines on one valid mutation.
    # When the duplicate-preserving HTTP scenario runs.
    outcome = exercise_header_lines(("retry-a", "retry-a"))
    # Then transport rejects before mutation or audit.
    assert outcome.response.status_code == 400
    assert b"invalid_idempotency_key" in outcome.response.body
    assert (outcome.grant_count, outcome.audit_count) == (0, 0)


def test_comma_combined_idempotency_header_is_uncached_400() -> None:
    # Given one proxy-combined retry-key field.
    # When it crosses the real HTTP boundary.
    outcome = exercise_header_lines(("retry-a,retry-b",))
    # Then the same coarse uncached error has no side effects.
    assert outcome.response.status_code == 400
    assert b"invalid_idempotency_key" in outcome.response.body
    assert (outcome.grant_count, outcome.audit_count) == (0, 0)


@pytest.mark.parametrize("raw_key", ("", " ", "\t", "retry\x01key", "réessayer", "a" * 129))
def test_empty_whitespace_control_non_ascii_and_overlong_keys_are_uncached_400(
    raw_key: str,
) -> None:
    # Given one forbidden raw key grammar class.
    # When it crosses the real HTTP boundary.
    outcome = exercise_header_lines((raw_key,))
    # Then the request is rejected without mutation or audit.
    assert outcome.response.status_code == 400
    assert b"invalid_idempotency_key" in outcome.response.body
    assert (outcome.grant_count, outcome.audit_count) == (0, 0)


def test_invalid_key_is_checked_after_authentication_and_body_parsing() -> None:
    # Given invalid keys paired with unauthenticated, malformed, and valid requests.
    # When all precedence boundaries run on one live server.
    outcome = exercise_validation_precedence()
    # Then auth/body errors win and only the parsed request reaches key validation.
    unauthenticated, malformed, invalid_key = outcome.responses
    assert tuple(response.status_code for response in outcome.responses) == (401, 400, 400)
    assert b"invalid_idempotency_key" not in unauthenticated.body
    assert b"invalid_idempotency_key" not in malformed.body
    assert b"invalid_idempotency_key" in invalid_key.body
    assert (outcome.grant_count, outcome.audit_count) == (0, 0)


def test_raw_idempotency_key_is_absent_from_repr_error_log_audit_and_database(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given a secret-bearing key and a fully absent keyring.
    raw_key = "never-store-this-retry-key"
    caplog.set_level(logging.ERROR)
    # When the keyed SQLite request fails closed.
    outcome = exercise_raw_key_redaction(tmp_path / "raw.sqlite3", raw_key)
    # Then neither the response nor persisted surfaces contain the raw value.
    assert outcome.response.status_code == 503
    assert b"idempotency_unavailable" in outcome.response.body
    assert raw_key not in repr(outcome.response)
    assert raw_key not in outcome.database_dump
    assert raw_key not in outcome.audit_text
    assert raw_key.encode("ascii") not in outcome.database_bytes
    assert any(
        record.levelno >= logging.ERROR and "idempotency_unavailable" in record.getMessage()
        for record in caplog.records
    )
    assert all(raw_key not in repr(record.__dict__) for record in caplog.records)


def test_fingerprint_normalizes_object_order_and_whitespace_but_preserves_array_order() -> None:
    # Given equivalent object text and one ordered-array permutation.
    from dataclasses import replace

    from vinctor_service.idempotency_crypto import build_request_fingerprint
    from vinctor_service.idempotency_models import RequestFingerprintInput

    request = RequestFingerprintInput(
        method="POST",
        path="/v1/grants",
        authenticated_workspace_id="ws_main",
        authenticated_principal="workspace:ws_main",
        operation="grant.issue.v1",
        request_body=b'{"scopes":["a","b"],"ttl":60}',
    )
    # When the canonical crypto codec fingerprints each raw body.
    first = build_request_fingerprint(request)
    reordered = build_request_fingerprint(
        replace(request, request_body=b'{ "ttl" : 60, "scopes" : [ "a", "b" ] }')
    )
    changed = build_request_fingerprint(
        replace(request, request_body=b'{"ttl":60,"scopes":["b","a"]}')
    )
    # Then formatting normalizes while array order remains significant.
    assert first == reordered
    assert first != changed


def test_fingerprint_includes_defaults_path_id_reason_and_empty_body_sentinel() -> None:
    # Given distinct effective/default/path/reason/empty-body route values.
    from vinctor_service.idempotency_crypto import build_request_fingerprint
    from vinctor_service.idempotency_models import RequestFingerprintInput

    variants = (
        RequestFingerprintInput(
            "POST", "/v1/tokens", "ws", "agent:a", "subject_token.mint.v1", b'{"pop":false}'
        ),
        RequestFingerprintInput(
            "POST", "/v1/tokens", "ws", "agent:a", "subject_token.mint.v1", b'{"pop":true}'
        ),
        RequestFingerprintInput(
            "POST",
            "/v1/grant-requests/a/approve",
            "ws",
            "workspace:ws",
            "grant_request.approve.v1",
            b'{"decision_reason":null}',
        ),
        RequestFingerprintInput(
            "POST",
            "/v1/grant-requests/b/approve",
            "ws",
            "workspace:ws",
            "grant_request.approve.v1",
            b'{"decision_reason":null}',
        ),
        RequestFingerprintInput(
            "POST",
            "/v1/grant-requests/a/reject",
            "ws",
            "workspace:ws",
            "grant_request.reject.v1",
            b'{"decision_reason":"because"}',
        ),
        RequestFingerprintInput(
            "POST",
            "/v1/grant-requests/a/auto-approve",
            "ws",
            "workspace:ws",
            "grant_request.auto_approve.v1",
            b"",
        ),
    )
    # When every variant is fingerprinted.
    fingerprints = tuple(build_request_fingerprint(variant) for variant in variants)
    # Then no distinct effective request aliases another.
    assert len(set(fingerprints)) == len(fingerprints)


def test_same_key_is_scoped_by_workspace_principal_and_operation(tmp_path: Path) -> None:
    # Given one configured database and one repeated raw key.
    # When workspace/grant and agent/token operations use it.
    grant_status, token_status, other_workspace_status, result_count = exercise_scoped_operations(
        tmp_path / "scope.sqlite3"
    )
    # Then workspace, principal, and operation differences persist three scoped results.
    assert (grant_status, token_status, other_workspace_status, result_count) == (
        201,
        201,
        201,
        3,
    )


def test_same_key_and_different_fingerprint_returns_409_without_mutation_or_reservation(
    tmp_path: Path,
) -> None:
    # Given one successful keyed mutation.
    # When the same key is reused with a different fingerprint.
    outcome = exercise_conflict(tmp_path / "conflict.sqlite3")
    # Then the exact conflict consumes no additional persistent work.
    assert outcome.first.status_code == 201
    assert _wire(outcome.conflict) == (
        409,
        "application/json",
        75,
        b'{"error": "idempotency_key_conflict", "reason": "idempotency_key_conflict"}',
    )
    assert outcome.after_conflict == outcome.after_first


def test_unkeyed_response_bytes_match_pinned_legacy_bytes() -> None:
    # Given the new pure response encoder and fixed legacy payload.
    from vinctor_service.idempotency_http import encode_json_response
    from vinctor_service.v1_http import V1HttpResponse

    # When it encodes the response once.
    encoded = encode_json_response(V1HttpResponse(status_code=201, body={"z": 1, "a": "legacy"}))
    # Then the stable wire tuple matches independent historical bytes.
    assert (encoded.status_code, encoded.content_type, len(encoded.body), encoded.body) == (
        201,
        "application/json",
        23,
        b'{"a": "legacy", "z": 1}',
    )


def test_keyed_first_response_and_replay_have_exact_status_content_type_and_body_bytes(
    tmp_path: Path,
) -> None:
    # Given a configured keyed grant route.
    # When the exact request is sent twice.
    outcome = exercise_replay(tmp_path / "wire.sqlite3", ROUTE_CASES[0])
    # Then replay preserves the complete stable wire tuple.
    assert outcome.first.status_code == 201
    assert _wire(outcome.replay) == _wire(outcome.first)


def test_replay_does_not_reenter_callback_policy_audit_anchor_or_export(
    tmp_path: Path,
) -> None:
    # Given persisted state counters around one keyed grant.
    # When the exact response is replayed.
    outcome = exercise_replay(tmp_path / "bypass.sqlite3", ROUTE_CASES[0])
    # Then only the first request changes business, audit, result, and reservation state.
    assert _wire(outcome.replay) == _wire(outcome.first)
    assert outcome.after_first.grants == outcome.before.grants + 1
    assert outcome.after_first.audits == outcome.before.audits + 1
    assert outcome.after_first.results == outcome.before.results + 1
    assert outcome.after_first.reservations == outcome.before.reservations + 1
    assert outcome.after_replay == outcome.after_first


def test_fully_absent_keyring_returns_503_after_auth_and_parse_before_mutation() -> None:
    # Given a fully absent keyring and an authenticated parsed request.
    # When the valid keyed mutation crosses the live route.
    outcome = exercise_absent_keyring()
    # Then fixed 503 occurs before mutation or audit.
    assert _wire(outcome.response) == (
        503,
        "application/json",
        73,
        b'{"error": "idempotency_unavailable", "reason": "idempotency_unavailable"}',
    )
    assert (outcome.grant_count, outcome.audit_count) == (0, 0)


@pytest.mark.parametrize("case", ROUTE_CASES, ids=lambda case: case.label)
def test_seven_route_terminal_matrix_is_cached_exactly_once(
    case: RouteCase,
    tmp_path: Path,
) -> None:
    # Given one cacheable terminal request on a protected route.
    # When the same key/request is sent twice.
    outcome = exercise_replay(tmp_path / f"{case.operation}.sqlite3", case)
    # Then exactly one state/audit/result/reservation change is cached and replayed.
    assert_expected_terminal_response(
        outcome.first,
        EXPECTED_TERMINAL_RESPONSES[case.label],
    )
    assert _wire(outcome.replay) == _wire(outcome.first)
    assert outcome.after_first.results == outcome.before.results + 1
    assert outcome.after_first.reservations == outcome.before.reservations + 1
    assert state_value(outcome.after_first, case.state_field) == (
        state_value(outcome.before, case.state_field) + case.state_delta
    )
    assert outcome.after_first.audits == outcome.before.audits + case.audit_delta
    assert outcome.after_replay == outcome.after_first
