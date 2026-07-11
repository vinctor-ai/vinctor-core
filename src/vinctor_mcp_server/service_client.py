from __future__ import annotations

import json
from collections.abc import Callable
from http.client import HTTPConnection, HTTPSConnection
from typing import Any, Protocol
from urllib.parse import quote, urlencode, urlsplit


class HttpConnection(Protocol):
    def request(
        self,
        method: str,
        path: str,
        body: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None: ...

    def getresponse(self) -> Any: ...

    def close(self) -> None: ...


ConnectionFactory = Callable[[str, int, int], HttpConnection]


class VinctorServiceClientError(Exception):
    pass


class VinctorServiceClient:
    def __init__(
        self,
        *,
        endpoint: str,
        workspace_key: str,
        timeout: int = 5,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise ValueError("endpoint must be an http(s) URL with a host")
        self._scheme = parsed.scheme
        self._host = parsed.hostname
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._workspace_key = workspace_key
        self._timeout = timeout
        self._connection_factory = connection_factory or self._default_connection

    def status(self) -> dict[str, Any]:
        return self._request_json("GET", "/healthz", workspace_auth=False)

    def list_boundaries(self) -> dict[str, Any]:
        return self._request_json("GET", "/v1/boundaries")

    def get_boundary(self, boundary_id: str) -> dict[str, Any]:
        return self._request_json("GET", f"/v1/boundaries/{_path_part(boundary_id)}")

    def get_grant(self, grant_ref: str) -> dict[str, Any]:
        return self._request_json("GET", f"/v1/grants/{_path_part(grant_ref)}")

    def list_grants(
        self,
        *,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        query = _query({"agent_id": agent_id, "status": status})
        suffix = f"?{query}" if query else ""
        return self._request_json("GET", f"/v1/grants{suffix}")

    def list_audit_events(
        self,
        *,
        limit: int = 20,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        request_id: str | None = None,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        query = _query(
            {
                "agent_id": agent_id,
                "event_type": event_type,
                "grant_ref": grant_ref,
                "boundary_id": boundary_id,
                "request_id": request_id,
                "limit": str(limit),
            }
        )
        return self._request_json("GET", f"/v1/audit-events?{query}")

    def get_audit_event(self, event_id: str) -> dict[str, Any]:
        return self._request_json("GET", f"/v1/audit-events/{_path_part(event_id)}")

    def list_grant_requests(self) -> dict[str, Any]:
        return self._request_json("GET", "/v1/grant-requests")

    def get_grant_request(self, request_id: str) -> dict[str, Any]:
        return self._request_json("GET", f"/v1/grant-requests/{_path_part(request_id)}")

    def list_auto_approval_rules(self) -> dict[str, Any]:
        return self._request_json("GET", "/v1/auto-approval-rules")

    def approve_grant_request(
        self,
        request_id: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            f"/v1/grant-requests/{_path_part(request_id)}/approve",
            body=_decision_body(reason),
        )

    def reject_grant_request(
        self,
        request_id: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            f"/v1/grant-requests/{_path_part(request_id)}/reject",
            body=_decision_body(reason),
        )

    def revoke_grant(self, grant_ref: str) -> dict[str, Any]:
        return self._request_json("POST", f"/v1/grants/{_path_part(grant_ref)}/revoke")

    def issue_grant(
        self, *, agent_id: str, scopes: list[str], ttl_seconds: int
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            "/v1/grants",
            body={"agent_id": agent_id, "scopes": list(scopes), "ttl_seconds": ttl_seconds},
        )

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        workspace_auth: bool = True,
        body: object | None = None,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        request_body = None
        if workspace_auth:
            headers["X-Workspace-Key"] = self._workspace_key
        if body is not None:
            headers["Content-Type"] = "application/json"
            request_body = json.dumps(body)

        conn = self._connection_factory(self._host, self._port, self._timeout)
        try:
            conn.request(method, path, body=request_body, headers=headers)
            response = conn.getresponse()
            response_text = response.read().decode("utf-8")
        finally:
            conn.close()

        try:
            response_body = json.loads(response_text) if response_text else {}
        except json.JSONDecodeError as error:
            raise VinctorServiceClientError("service returned non-JSON response") from error
        if not isinstance(response_body, dict):
            raise VinctorServiceClientError("service returned non-object JSON response")
        if response.status >= 400:
            error = str(response_body.get("error", "request_failed"))
            reason = str(response_body.get("reason", error))
            raise VinctorServiceClientError(f"{response.status} {error}: {reason}")
        return response_body

    def _default_connection(self, host: str, port: int, timeout: int) -> HttpConnection:
        if self._scheme == "https":
            return HTTPSConnection(host, port, timeout=timeout)
        return HTTPConnection(host, port, timeout=timeout)


def _decision_body(reason: str | None) -> dict[str, str] | None:
    # The operator endpoint's _decision_reason parser accepts no body (None) as
    # "no reason" and only the "decision_reason" key otherwise; an empty/None
    # reason sends no body at all.
    if reason is None or reason == "":
        return None
    return {"decision_reason": reason}


def _path_part(value: str) -> str:
    if value == "":
        raise ValueError("path value must be non-empty")
    return quote(value, safe="")


def _query(values: dict[str, str | None]) -> str:
    return urlencode({key: value for key, value in values.items() if value is not None})
