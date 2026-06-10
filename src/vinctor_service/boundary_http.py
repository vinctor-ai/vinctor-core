from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, cast

from vinctor_core import Boundary, BoundaryRegistrationInput
from vinctor_core.models import BoundaryMode
from vinctor_service.v1_http import V1HttpResponse


@dataclass(frozen=True)
class WorkspaceIdentity:
    workspace_id: str


class BoundaryAdminService(Protocol):
    def register_boundary(
        self,
        registration: BoundaryRegistrationInput,
        *,
        now: datetime | None = None,
        boundary_id: str | None = None,
    ) -> Boundary: ...

    def list_boundaries(self, workspace_id: str) -> tuple[Boundary, ...]: ...

    def get_boundary(self, *, boundary_id: str, workspace_id: str) -> Boundary | None: ...

    def disable_boundary(
        self,
        *,
        boundary_id: str,
        workspace_id: str,
        now: datetime | None = None,
    ) -> Boundary | None: ...

    def enable_boundary(
        self,
        *,
        boundary_id: str,
        workspace_id: str,
        now: datetime | None = None,
    ) -> Boundary | None: ...


def handle_v1_boundaries_http(
    *,
    method: str,
    path: str,
    headers: Mapping[str, str],
    body: object,
    workspace_identities: Mapping[str, WorkspaceIdentity],
    service: BoundaryAdminService,
    now: datetime,
) -> V1HttpResponse:
    identity = _workspace_identity(headers, workspace_identities)
    if identity is None:
        return _error(401, "authentication_required", "valid X-Workspace-Key header is required")

    if path == "/v1/boundaries":
        if method == "POST":
            return _create_boundary(body, identity=identity, service=service, now=now)
        if method == "GET":
            return V1HttpResponse(
                status_code=200,
                body={
                    "boundaries": [
                        _boundary_body(boundary)
                        for boundary in service.list_boundaries(identity.workspace_id)
                    ]
                },
            )
        return _error(405, "method_not_allowed", "GET or POST is required for /v1/boundaries")

    prefix = "/v1/boundaries/"
    if path.startswith(prefix):
        boundary_id = path.removeprefix(prefix)
        parts = boundary_id.split("/")
        if len(parts) == 1 and parts[0] != "":
            if method != "GET":
                return _error(
                    405,
                    "method_not_allowed",
                    "GET is required for /v1/boundaries/{id}",
                )
            boundary = service.get_boundary(
                boundary_id=parts[0],
                workspace_id=identity.workspace_id,
            )
            if boundary is None:
                return _error(404, "boundary_not_found", "boundary was not found")
            return V1HttpResponse(status_code=200, body=_boundary_body(boundary))

        if len(parts) == 2 and parts[0] != "" and parts[1] in {"disable", "enable"}:
            if method != "POST":
                return _error(
                    405,
                    "method_not_allowed",
                    f"POST is required for /v1/boundaries/{{id}}/{parts[1]}",
                )
            return _set_boundary_status(
                service=service,
                boundary_id=parts[0],
                workspace_id=identity.workspace_id,
                action=parts[1],
                now=now,
            )

        if boundary_id == "" or "/" in boundary_id:
            return _error(404, "not_found", "route not found")

    return _error(404, "not_found", "route not found")


def _workspace_identity(
    headers: Mapping[str, str],
    workspace_identities: Mapping[str, WorkspaceIdentity],
) -> WorkspaceIdentity | None:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    workspace_key = normalized_headers.get("x-workspace-key")
    if workspace_key is None:
        return None
    return workspace_identities.get(workspace_key)


def _create_boundary(
    body: object,
    *,
    identity: WorkspaceIdentity,
    service: BoundaryAdminService,
    now: datetime,
) -> V1HttpResponse:
    parsed = _parse_create_body(body)
    if isinstance(parsed, V1HttpResponse):
        return parsed

    try:
        boundary = service.register_boundary(
            BoundaryRegistrationInput(
                workspace_id=identity.workspace_id,
                name=parsed["name"],
                runtime=parsed["runtime"],
                boundary_type=parsed["boundary_type"],
                mode=cast(BoundaryMode, parsed["mode"]),
            ),
            now=now,
        )
    except ValueError as error:
        return _error(400, "invalid_request", str(error))

    return V1HttpResponse(status_code=201, body=_boundary_body(boundary))


def _set_boundary_status(
    *,
    service: BoundaryAdminService,
    boundary_id: str,
    workspace_id: str,
    action: str,
    now: datetime,
) -> V1HttpResponse:
    if action == "disable":
        boundary = service.disable_boundary(
            boundary_id=boundary_id,
            workspace_id=workspace_id,
            now=now,
        )
    else:
        boundary = service.enable_boundary(
            boundary_id=boundary_id,
            workspace_id=workspace_id,
            now=now,
        )

    if boundary is None:
        return _error(404, "boundary_not_found", "boundary was not found")
    return V1HttpResponse(status_code=200, body=_boundary_body(boundary))


def _parse_create_body(body: object) -> dict[str, str] | V1HttpResponse:
    if not isinstance(body, dict):
        return _error(400, "invalid_request", "request body must be a JSON object")

    required_fields = {"name", "runtime", "boundary_type", "mode"}
    body_fields = set(body)
    missing = sorted(required_fields - body_fields)
    extra = sorted(body_fields - required_fields)
    if missing:
        return _error(400, "invalid_request", f"missing required field: {missing[0]}")
    if extra:
        return _error(400, "invalid_request", f"unexpected field: {extra[0]}")

    parsed: dict[str, str] = {}
    for field in sorted(required_fields):
        value = body[field]
        if not isinstance(value, str) or value == "":
            return _error(400, "invalid_request", f"{field} must be a non-empty string")
        parsed[field] = value
    return parsed


def _boundary_body(boundary: Boundary) -> dict[str, str]:
    return {
        "boundary_id": boundary.boundary_id,
        "name": boundary.name,
        "runtime": boundary.runtime,
        "boundary_type": boundary.boundary_type,
        "mode": boundary.mode,
        "status": boundary.status,
    }


def _error(status_code: int, error: str, reason: str) -> V1HttpResponse:
    return V1HttpResponse(status_code=status_code, body={"error": error, "reason": reason})
