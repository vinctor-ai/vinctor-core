from __future__ import annotations

from typing import Protocol

from vinctor_core.models import Grant


class GrantRepository(Protocol):
    def get_by_ref(self, grant_ref: str) -> Grant | None: ...


class GrantLifecycleRepository(GrantRepository, Protocol):
    def insert(self, grant: Grant) -> None: ...

    def revoke(self, *, grant_ref: str, workspace_id: str) -> Grant | None: ...


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
