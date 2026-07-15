from __future__ import annotations

import json
import sqlite3
import sys
from datetime import UTC, datetime
from http.client import HTTPConnection
from threading import Thread
from types import SimpleNamespace

import pytest

from vinctor_service.local_http import create_v1_http_server
from vinctor_service.oidc import (
    OidcConfig,
    OidcPrincipal,
    PyJwtOidcTokenVerifier,
    load_oidc_config,
    principal_from_claims,
)
from vinctor_service.sqlite import SQLiteV1Service

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)


class _Verifier:
    def __init__(self, principals: dict[str, OidcPrincipal]) -> None:
        self._principals = principals

    def verify(self, token: str) -> OidcPrincipal | None:
        return self._principals.get(token)


def _config() -> OidcConfig:
    return OidcConfig(
        issuer="https://identity.example.com",
        audience="vinctor-service",
        jwks_url="https://identity.example.com/.well-known/jwks.json",
    )


def test_oidc_is_disabled_when_core_settings_are_absent() -> None:
    assert load_oidc_config({}) is None


def test_oidc_rejects_partial_core_settings() -> None:
    with pytest.raises(ValueError, match="VINCTOR_OIDC_AUDIENCE"):
        load_oidc_config(
            {
                "VINCTOR_OIDC_ISSUER": "https://identity.example.com",
                "VINCTOR_OIDC_JWKS_URL": "https://identity.example.com/jwks.json",
            }
        )


def test_oidc_config_reads_claim_group_and_algorithm_settings() -> None:
    config = load_oidc_config(
        {
            "VINCTOR_OIDC_ISSUER": "https://identity.example.com",
            "VINCTOR_OIDC_AUDIENCE": "vinctor-service",
            "VINCTOR_OIDC_JWKS_URL": "https://identity.example.com/jwks.json",
            "VINCTOR_OIDC_GROUPS_CLAIM": "roles",
            "VINCTOR_OIDC_WORKSPACE_CLAIM": "tenant",
            "VINCTOR_OIDC_OPERATOR_GROUP": "ops",
            "VINCTOR_OIDC_AUDITOR_GROUP": "audit",
            "VINCTOR_OIDC_SERVICE_OPERATOR_GROUP": "platform",
            "VINCTOR_OIDC_ALGORITHMS": "RS256,ES256",
        }
    )

    assert config is not None
    assert config.groups_claim == "roles"
    assert config.workspace_claim == "tenant"
    assert config.operator_group == "ops"
    assert config.auditor_group == "audit"
    assert config.service_operator_group == "platform"
    assert config.algorithms == ("RS256", "ES256")


def test_oidc_rejects_symmetric_signing_algorithms() -> None:
    with pytest.raises(ValueError, match="asymmetric"):
        OidcConfig(
            issuer="https://identity.example.com",
            audience="vinctor-service",
            jwks_url="https://identity.example.com/jwks.json",
            algorithms=("HS256",),
        )


def test_claims_map_groups_to_workspace_scoped_roles() -> None:
    principal = principal_from_claims(
        _config(),
        {
            "sub": "user-123",
            "vinctor_workspace_id": "ws_main",
            "groups": ["vinctor-operator", "vinctor-auditor"],
        },
    )

    assert principal == OidcPrincipal(
        subject="user-123",
        workspace_id="ws_main",
        roles=frozenset({"operator", "auditor"}),
    )


@pytest.mark.parametrize(
    "claims",
    [
        {"sub": "", "groups": ["vinctor-operator"]},
        {"sub": "user-123", "groups": "vinctor-operator"},
        {
            "sub": "user-123",
            "groups": ["vinctor-operator"],
            "vinctor_workspace_id": 123,
        },
    ],
)
def test_invalid_identity_claim_shapes_are_rejected(claims: dict[str, object]) -> None:
    assert principal_from_claims(_config(), claims) is None


def test_pyjwt_verifier_requires_configured_issuer_audience_and_algorithm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class _SigningKey:
        key = "public-key"

    class _JwksClient:
        def __init__(self, url: str) -> None:
            captured["jwks_url"] = url

        def get_signing_key_from_jwt(self, token: str) -> _SigningKey:
            captured["token"] = token
            return _SigningKey()

    def decode(token: str, key: str, **kwargs: object) -> dict[str, object]:
        captured.update({"decoded_token": token, "key": key, **kwargs})
        return {
            "sub": "user-123",
            "vinctor_workspace_id": "ws_main",
            "groups": ["vinctor-operator"],
        }

    fake_jwt = SimpleNamespace(
        PyJWKClient=_JwksClient,
        PyJWTError=ValueError,
        decode=decode,
    )
    monkeypatch.setitem(sys.modules, "jwt", fake_jwt)

    principal = PyJwtOidcTokenVerifier(_config()).verify("signed-token")

    assert principal is not None
    assert principal.roles == frozenset({"operator"})
    assert captured["algorithms"] == ["RS256"]
    assert captured["issuer"] == "https://identity.example.com"
    assert captured["audience"] == "vinctor-service"
    assert captured["options"] == {"require": ["exp", "iss", "aud", "sub"]}


def test_oidc_roles_are_enforced_by_http_surface() -> None:
    service = SQLiteV1Service(sqlite3.connect(":memory:", check_same_thread=False))
    service.record_auth_failure(surface="enforce", now=NOW)
    verifier = _Verifier(
        {
            "operator-token": OidcPrincipal(
                subject="operator-1",
                workspace_id="ws_main",
                roles=frozenset({"operator"}),
            ),
            "auditor-token": OidcPrincipal(
                subject="auditor-1",
                workspace_id="ws_main",
                roles=frozenset({"auditor"}),
            ),
            "service-token": OidcPrincipal(
                subject="service-operator-1",
                workspace_id=None,
                roles=frozenset({"service_operator"}),
            ),
        }
    )
    server = create_v1_http_server(
        ("127.0.0.1", 0),
        service=service,
        agent_identities={},
        oidc_token_verifier=verifier,
        clock=lambda: NOW,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        operator_status, _ = _request(
            server,
            "POST",
            "/v1/boundaries",
            token="operator-token",
            body={
                "name": "oidc-boundary",
                "runtime": "claude-code",
                "boundary_type": "pretooluse",
                "mode": "fail_closed",
            },
        )
        auditor_read_status, _ = _request(
            server,
            "GET",
            "/v1/audit-events",
            token="auditor-token",
        )
        auditor_write_status, _ = _request(
            server,
            "POST",
            "/v1/boundaries",
            token="auditor-token",
            body={},
        )
        service_read_status, service_body = _request(
            server,
            "GET",
            "/v1/service/audit/auth-failures",
            token="service-token",
        )
        service_workspace_status, _ = _request(
            server,
            "GET",
            "/v1/audit-events",
            token="service-token",
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        service.conn.close()

    assert operator_status == 201
    assert auditor_read_status == 200
    assert auditor_write_status == 401
    assert service_read_status == 200
    assert len(service_body["auth_failures"]) == 1
    assert service_workspace_status == 401


def _request(
    server,
    method: str,
    path: str,
    *,
    token: str,
    body: object | None = None,
) -> tuple[int, dict[str, object]]:
    connection = HTTPConnection(*server.server_address, timeout=5)
    raw_body = None if body is None else json.dumps(body)
    headers = {"Authorization": f"Bearer {token}"}
    if raw_body is not None:
        headers["Content-Type"] = "application/json"
    connection.request(method, path, body=raw_body, headers=headers)
    response = connection.getresponse()
    parsed = json.loads(response.read())
    connection.close()
    return response.status, parsed
