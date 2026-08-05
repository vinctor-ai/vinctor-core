from __future__ import annotations

from datetime import UTC, datetime

from vinctor_service import (
    InMemoryV1Service,
    WorkspaceIdentity,
    handle_v1_boundaries_http,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def service() -> InMemoryV1Service:
    return InMemoryV1Service()


def identities() -> dict[str, WorkspaceIdentity]:
    return {
        "workspace_key_main": WorkspaceIdentity(workspace_id="ws_main"),
        "workspace_key_other": WorkspaceIdentity(workspace_id="ws_other"),
    }


def create_body(
    *,
    name: str = "claude-code-local",
    runtime: str = "claude-code",
    boundary_type: str = "pretooluse",
    mode: str = "fail_closed",
) -> dict[str, str]:
    return {
        "name": name,
        "runtime": runtime,
        "boundary_type": boundary_type,
        "mode": mode,
    }


def call(
    service_instance: InMemoryV1Service,
    *,
    method: str = "POST",
    path: str = "/v1/boundaries",
    headers: dict[str, str] | None = None,
    body: object | None = None,
):
    return handle_v1_boundaries_http(
        method=method,
        path=path,
        headers=(
            {"X-Workspace-Key": "workspace_key_main"}
            if headers is None
            else headers
        ),
        body=create_body() if body is None else body,
        workspace_identities=identities(),
        service=service_instance,
        now=NOW,
    )


def test_boundary_http_creates_boundary_for_workspace() -> None:
    svc = service()

    response = call(svc)

    assert response.status_code == 201
    assert response.body["boundary_id"].startswith("bnd_")
    assert response.body["name"] == "claude-code-local"
    assert response.body["runtime"] == "claude-code"
    assert response.body["boundary_type"] == "pretooluse"
    assert response.body["mode"] == "fail_closed"
    assert response.body["status"] == "active"
    assert len(svc.list_boundaries("ws_main")) == 1


def test_boundary_http_lists_workspace_boundaries() -> None:
    svc = service()
    created = call(svc)

    response = call(svc, method="GET", body=None)

    assert response.status_code == 200
    assert response.body == {"boundaries": [created.body]}


def test_boundary_http_gets_one_workspace_boundary() -> None:
    svc = service()
    created = call(svc)

    response = call(
        svc,
        method="GET",
        path=f"/v1/boundaries/{created.body['boundary_id']}",
        body=None,
    )

    assert response.status_code == 200
    assert response.body == created.body


def test_boundary_http_requires_workspace_key() -> None:
    svc = service()

    response = call(svc, headers={}, body=create_body())

    assert response.status_code == 401
    assert response.body["error"] == "authentication_required"
    assert svc.list_boundaries("ws_main") == ()


def test_boundary_http_rejects_unknown_workspace_key() -> None:
    svc = service()

    response = call(
        svc,
        headers={"X-Workspace-Key": "workspace_key_missing"},
        body=create_body(),
    )

    assert response.status_code == 401
    assert response.body["error"] == "authentication_required"
    assert svc.list_boundaries("ws_main") == ()


def test_boundary_http_keeps_create_body_strict() -> None:
    svc = service()

    missing = call(svc, body={"name": "claude-code-local"})
    extra = call(svc, body={**create_body(), "status": "disabled"})
    non_string = call(svc, body={**create_body(), "runtime": 123})

    assert missing.status_code == 400
    assert missing.body["error"] == "invalid_request"
    assert extra.status_code == 400
    assert extra.body["error"] == "invalid_request"
    assert non_string.status_code == 400
    assert non_string.body["error"] == "invalid_request"
    assert svc.list_boundaries("ws_main") == ()


def test_boundary_http_rejects_invalid_mode() -> None:
    svc = service()

    response = call(svc, body=create_body(mode="fail_open"))

    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"
    assert response.body["reason"] == "boundary mode must be fail_closed"
    assert svc.list_boundaries("ws_main") == ()


def test_boundary_http_rejects_duplicate_name() -> None:
    svc = service()
    call(svc)

    response = call(svc)

    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"
    assert response.body["reason"] == "boundary name must be unique within workspace"


def test_boundary_http_get_does_not_cross_workspace() -> None:
    svc = service()
    created = call(svc)

    response = call(
        svc,
        method="GET",
        path=f"/v1/boundaries/{created.body['boundary_id']}",
        headers={"X-Workspace-Key": "workspace_key_other"},
        body=None,
    )

    assert response.status_code == 404
    assert response.body["error"] == "boundary_not_found"


def test_boundary_http_list_is_workspace_scoped() -> None:
    svc = service()
    call(svc)

    response = call(
        svc,
        method="GET",
        headers={"X-Workspace-Key": "workspace_key_other"},
        body=None,
    )

    assert response.status_code == 200
    assert response.body == {"boundaries": []}


def test_boundary_http_rejects_unsupported_methods() -> None:
    svc = service()

    response = call(svc, method="DELETE")

    assert response.status_code == 405
    assert response.body["error"] == "method_not_allowed"


def test_boundary_http_disables_and_enables_boundary() -> None:
    svc = service()
    created = call(svc)
    boundary_id = created.body["boundary_id"]

    disabled = call(
        svc,
        method="POST",
        path=f"/v1/boundaries/{boundary_id}/disable",
    )
    enabled = call(
        svc,
        method="POST",
        path=f"/v1/boundaries/{boundary_id}/enable",
    )

    assert disabled.status_code == 200
    assert disabled.body["boundary_id"] == boundary_id
    assert disabled.body["status"] == "disabled"
    assert enabled.status_code == 200
    assert enabled.body["boundary_id"] == boundary_id
    assert enabled.body["status"] == "active"


def test_boundary_http_disable_does_not_cross_workspace() -> None:
    svc = service()
    created = call(svc)

    response = call(
        svc,
        method="POST",
        path=f"/v1/boundaries/{created.body['boundary_id']}/disable",
        headers={"X-Workspace-Key": "workspace_key_other"},
    )

    assert response.status_code == 404
    assert response.body["error"] == "boundary_not_found"
    assert svc.list_boundaries("ws_main")[0].status == "active"


def test_boundary_http_enable_returns_not_found_for_missing_boundary() -> None:
    svc = service()

    response = call(
        svc,
        method="POST",
        path="/v1/boundaries/bnd_missing/enable",
    )

    assert response.status_code == 404
    assert response.body["error"] == "boundary_not_found"


def test_boundary_http_status_routes_require_post() -> None:
    svc = service()
    created = call(svc)

    response = call(
        svc,
        method="GET",
        path=f"/v1/boundaries/{created.body['boundary_id']}/disable",
    )

    assert response.status_code == 405
    assert response.body["error"] == "method_not_allowed"
