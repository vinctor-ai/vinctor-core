from __future__ import annotations

from datetime import datetime
from typing import Protocol

from vinctor_core.models import Grant
from vinctor_service.models import AutoApprovalRule, GrantRequest, SubjectToken


class GrantRepository(Protocol):
    def get_by_ref(self, grant_ref: str) -> Grant | None: ...

    def list_grants_for_workspace(
        self,
        workspace_id: str,
        *,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> tuple[Grant, ...]: ...


class GrantLifecycleRepository(GrantRepository, Protocol):
    def insert(self, grant: Grant) -> None: ...

    def revoke(self, *, grant_ref: str, workspace_id: str) -> Grant | None: ...


class GrantRequestRepository(Protocol):
    def insert_request(self, request: GrantRequest) -> None: ...

    def get_request(self, request_id: str) -> GrantRequest | None: ...

    def list_requests_for_workspace(self, workspace_id: str) -> tuple[GrantRequest, ...]: ...

    def update_request(self, request: GrantRequest) -> None: ...


class AutoApprovalRuleRepository(Protocol):
    def add_rule(self, rule: AutoApprovalRule) -> None: ...

    def get_rule(self, rule_id: str) -> AutoApprovalRule | None: ...

    def list_rules_for_workspace(self, workspace_id: str) -> tuple[AutoApprovalRule, ...]: ...

    def update_rule(self, rule: AutoApprovalRule) -> None: ...


class SubjectTokenRepository(Protocol):
    def insert(self, token: SubjectToken) -> None: ...

    def get_by_hash(self, token_hash: str) -> SubjectToken | None: ...


class AgentEnforcementSettingsRepository(Protocol):
    def get_require_boundary(self, *, workspace_id: str, agent_id: str) -> bool: ...

    def get_require_boundary_setting(self, *, workspace_id: str, agent_id: str) -> bool | None: ...

    def is_boundary_required(self, *, workspace_id: str, agent_id: str) -> bool: ...

    def list_require_boundary(self, workspace_id: str) -> tuple[tuple[str, bool], ...]: ...

    def set_require_boundary(
        self, *, workspace_id: str, agent_id: str, require_boundary: bool, now: datetime
    ) -> None: ...


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

    def list_grants_for_workspace(
        self,
        workspace_id: str,
        *,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> tuple[Grant, ...]:
        return tuple(
            grant
            for grant in sorted(self._grants_by_ref.values(), key=lambda grant: grant.grant_id)
            if grant.workspace_id == workspace_id
            and (agent_id is None or grant.agent_id == agent_id)
            and (status is None or grant.status == status)
        )

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


class InMemoryAutoApprovalRuleRepository:
    def __init__(self, rules: tuple[AutoApprovalRule, ...] = ()) -> None:
        rules_by_id: dict[str, AutoApprovalRule] = {}
        for rule in rules:
            if rule.rule_id in rules_by_id:
                raise ValueError(f"duplicate auto-approval rule_id: {rule.rule_id}")
            rules_by_id[rule.rule_id] = rule
        self._rules_by_id = rules_by_id

    def add_rule(self, rule: AutoApprovalRule) -> None:
        if rule.rule_id in self._rules_by_id:
            raise ValueError(f"duplicate auto-approval rule_id: {rule.rule_id}")
        self._rules_by_id[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> AutoApprovalRule | None:
        return self._rules_by_id.get(rule_id)

    def list_rules_for_workspace(self, workspace_id: str) -> tuple[AutoApprovalRule, ...]:
        return tuple(
            rule for rule in self._rules_by_id.values() if rule.workspace_id == workspace_id
        )

    def update_rule(self, rule: AutoApprovalRule) -> None:
        if rule.rule_id not in self._rules_by_id:
            raise ValueError(f"unknown auto-approval rule_id: {rule.rule_id}")
        self._rules_by_id[rule.rule_id] = rule


class InMemorySubjectTokenRepository:
    def __init__(self, tokens: tuple[SubjectToken, ...] = ()) -> None:
        tokens_by_hash: dict[str, SubjectToken] = {}
        for token in tokens:
            if token.token_hash in tokens_by_hash:
                raise ValueError(f"duplicate subject token_hash: {token.token_hash}")
            tokens_by_hash[token.token_hash] = token
        self._tokens_by_hash = tokens_by_hash

    def insert(self, token: SubjectToken) -> None:
        if token.token_hash in self._tokens_by_hash:
            raise ValueError(f"duplicate subject token_hash: {token.token_hash}")
        self._tokens_by_hash[token.token_hash] = token

    def get_by_hash(self, token_hash: str) -> SubjectToken | None:
        return self._tokens_by_hash.get(token_hash)


class InMemoryAgentEnforcementSettingsRepository:
    def __init__(self) -> None:
        self._require_boundary: dict[tuple[str, str], bool] = {}

    def get_require_boundary(self, *, workspace_id: str, agent_id: str) -> bool:
        return self._require_boundary.get((workspace_id, agent_id), False)

    def get_require_boundary_setting(self, *, workspace_id: str, agent_id: str) -> bool | None:
        return self._require_boundary.get((workspace_id, agent_id))

    def is_boundary_required(self, *, workspace_id: str, agent_id: str) -> bool:
        agent = self._require_boundary.get((workspace_id, agent_id))
        if agent is not None:
            return agent
        return self._require_boundary.get((workspace_id, ""), False)

    def list_require_boundary(self, workspace_id: str) -> tuple[tuple[str, bool], ...]:
        return tuple(
            sorted(
                (agent_id, value)
                for (ws, agent_id), value in self._require_boundary.items()
                if ws == workspace_id
            )
        )

    def set_require_boundary(
        self, *, workspace_id: str, agent_id: str, require_boundary: bool, now: datetime
    ) -> None:
        self._require_boundary[(workspace_id, agent_id)] = require_boundary
