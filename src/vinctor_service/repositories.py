from __future__ import annotations

from typing import Protocol

from vinctor_core.models import Grant
from vinctor_service.models import GrantRequest


class GrantRepository(Protocol):
    def get_by_ref(self, grant_ref: str) -> Grant | None: ...


class GrantLifecycleRepository(GrantRepository, Protocol):
    def insert(self, grant: Grant) -> None: ...

    def revoke(self, *, grant_ref: str, workspace_id: str) -> Grant | None: ...


class GrantRequestRepository(Protocol):
    def insert_request(self, request: GrantRequest) -> None: ...

    def get_request(self, request_id: str) -> GrantRequest | None: ...

    def list_requests_for_workspace(self, workspace_id: str) -> tuple[GrantRequest, ...]: ...

    def update_request(self, request: GrantRequest) -> None: ...


class InMemoryGrantRepository:
    def __init__(self, grants: tuple[Grant, ...] = ()) -> None:
        grants_by_ref: dict[str, Grant] = {}
        for grant in grants:
            if grant.grant_ref in grants_by_ref:
                raise ValueError(f"duplicate grant_ref: {grant.grant_ref}")
            grants_by_ref[grant.grant_ref] = grant
        self._grants_by_ref = grants_by_ref

    def get_by_ref(self, grant_ref: str) -> Grant | None:
        return self._grants_by_ref.get(grant_ref)

    def insert(self, grant: Grant) -> None:
        if grant.grant_ref in self._grants_by_ref:
            raise ValueError(f"duplicate grant_ref: {grant.grant_ref}")
        self._grants_by_ref[grant.grant_ref] = grant

    def revoke(self, *, grant_ref: str, workspace_id: str) -> Grant | None:
        grant = self.get_by_ref(grant_ref)
        if grant is None or grant.workspace_id != workspace_id:
            return None
        grant.status = "revoked"
        return grant


class InMemoryGrantRequestRepository:
    def __init__(self, requests: tuple[GrantRequest, ...] = ()) -> None:
        requests_by_id: dict[str, GrantRequest] = {}
        for request in requests:
            if request.request_id in requests_by_id:
                raise ValueError(f"duplicate grant request_id: {request.request_id}")
            requests_by_id[request.request_id] = request
        self._requests_by_id = requests_by_id

    def insert_request(self, request: GrantRequest) -> None:
        if request.request_id in self._requests_by_id:
            raise ValueError(f"duplicate grant request_id: {request.request_id}")
        self._requests_by_id[request.request_id] = request

    def get_request(self, request_id: str) -> GrantRequest | None:
        return self._requests_by_id.get(request_id)

    def list_requests_for_workspace(self, workspace_id: str) -> tuple[GrantRequest, ...]:
        return tuple(
            request
            for request in self._requests_by_id.values()
            if request.workspace_id == workspace_id
        )

    def update_request(self, request: GrantRequest) -> None:
        if request.request_id not in self._requests_by_id:
            raise ValueError(f"unknown grant request_id: {request.request_id}")
        self._requests_by_id[request.request_id] = request
