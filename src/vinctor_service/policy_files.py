from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from vinctor_core.scope import is_valid_grant_scope
from vinctor_service.auto_approval import upsert_auto_approval_rule
from vinctor_service.grants import validate_issuable_scope_bounds
from vinctor_service.models import AutoApprovalRule
from vinctor_service.sqlite import SQLiteV1Service


@dataclass(frozen=True)
class PolicyApplyResult:
    workspace_id: str
    bounds_set: int
    rules_created: int
    rules_updated: int


def apply_policy_file(
    path: Path,
    *,
    service: SQLiteV1Service,
    workspace_id: str,
    applied_by: str,
    now: datetime,
) -> PolicyApplyResult:
    document = _load_policy_document(path)
    policy_workspace_id = document.get("workspace_id")
    if policy_workspace_id is not None and policy_workspace_id != workspace_id:
        raise ValueError("policy workspace_id does not match selected workspace")

    # Parse and fully validate the ENTIRE document (shape and scope grammar)
    # BEFORE any write. A malformed later entry must not leave earlier entries
    # committed, so apply is all-or-nothing with respect to validation. Only
    # read-only lookups (get_rule) happen during this phase.
    parsed_bounds = []
    for entry in _required_list(document, "agent_bounds"):
        parsed = _parse_bounds_entry(entry)
        validate_issuable_scope_bounds(tuple(parsed["scopes"]))
        parsed_bounds.append(parsed)

    prepared_rules = []
    for entry in _required_list(document, "auto_approval_rules"):
        parsed = _parse_rule_entry(entry)
        for scope in parsed["allowed_scopes"]:
            if not is_valid_grant_scope(scope):
                raise ValueError(f"invalid allowed scope: {scope}")
        rule_id = parsed.get("rule_id") or _stable_rule_id(
            workspace_id=workspace_id,
            name=parsed["name"],
            target_agent_id=parsed["target_agent_id"],
            scopes=tuple(parsed["allowed_scopes"]),
        )
        existing = service.auto_approval_rule_repository.get_rule(rule_id)
        prepared_rules.append(
            AutoApprovalRule(
                rule_id=rule_id,
                workspace_id=workspace_id,
                name=parsed["name"],
                target_agent_id=parsed["target_agent_id"],
                allowed_scopes=tuple(parsed["allowed_scopes"]),
                max_ttl_seconds=parsed["max_ttl_seconds"],
                status=parsed["status"],
                created_by=existing.created_by if existing is not None else applied_by,
                created_at=existing.created_at if existing is not None else now,
                updated_by=applied_by if existing is not None else None,
                updated_at=now if existing is not None else None,
            )
        )

    parsed_require_boundary = _parse_require_boundary(document)

    # Every entry validated; apply all writes.
    for parsed in parsed_bounds:
        service.set_agent_issuable_scope_bounds(
            workspace_id=workspace_id,
            agent_id=parsed["agent_id"],
            scopes=tuple(parsed["scopes"]),
            now=now,
        )

    rules_created = 0
    rules_updated = 0
    for rule in prepared_rules:
        action = upsert_auto_approval_rule(
            rule_repository=service.auto_approval_rule_repository,
            rule=rule,
        )
        if action == "created":
            rules_created += 1
        else:
            rules_updated += 1

    # require_boundary enables only (additive); disabling stays a CLI action.
    if parsed_require_boundary["workspace"] is not None:
        service.agent_enforcement_settings_repository.set_require_boundary(
            workspace_id=workspace_id,
            agent_id="",
            require_boundary=parsed_require_boundary["workspace"],
            now=now,
        )
    for agent_id in parsed_require_boundary["agents"]:
        service.agent_enforcement_settings_repository.set_require_boundary(
            workspace_id=workspace_id,
            agent_id=agent_id,
            require_boundary=True,
            now=now,
        )

    return PolicyApplyResult(
        workspace_id=workspace_id,
        bounds_set=len(parsed_bounds),
        rules_created=rules_created,
        rules_updated=rules_updated,
    )


def export_policy_document(
    *,
    service: SQLiteV1Service,
    workspace_id: str,
) -> dict[str, object]:
    document: dict[str, object] = {
        "version": 1,
        "workspace_id": workspace_id,
        "agent_bounds": [
            {
                "agent_id": agent_id,
                "scopes": list(scopes),
            }
            for agent_id, scopes in service.scope_bounds_repository.list_bounds_for_workspace(
                workspace_id
            )
        ],
        "auto_approval_rules": [
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "target_agent_id": rule.target_agent_id,
                "allowed_scopes": list(rule.allowed_scopes),
                # Emit the same `max_ttl` key the apply input uses (round-trip
                # symmetry) as a string duration so re-apply's isinstance(str)
                # path accepts it. apply rejects setting BOTH keys, so we emit
                # exactly one; it still accepts the legacy max_ttl_seconds key
                # for anyone who wrote it explicitly.
                "max_ttl": f"{rule.max_ttl_seconds}s",
                "status": rule.status,
            }
            for rule in service.list_auto_approval_rules(workspace_id=workspace_id)
        ],
    }

    rows = service.agent_enforcement_settings_repository.list_require_boundary(workspace_id)
    if rows:
        block: dict[str, object] = {}
        for agent_id, value in rows:
            if agent_id == "":
                block["workspace"] = value
        agents = sorted(agent_id for agent_id, value in rows if agent_id != "" and value)
        if agents:
            block["agents"] = agents
        document["require_boundary"] = block

    return document


def write_policy_file(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(document, sort_keys=False, allow_unicode=False),
        encoding="utf-8",
    )


def read_policy_file(path: Path) -> dict[str, object]:
    return _load_policy_document(path)


def _load_policy_document(path: Path) -> dict[str, object]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"could not read policy file: {path}") from error
    except yaml.YAMLError as error:
        raise ValueError(f"invalid YAML policy file: {error}") from error

    if not isinstance(loaded, dict):
        raise ValueError("policy file must contain a mapping")
    extra = sorted(
        set(loaded)
        - {"version", "workspace_id", "agent_bounds", "auto_approval_rules", "require_boundary"}
    )
    if extra:
        raise ValueError(f"unexpected policy field: {extra[0]}")
    version = loaded.get("version")
    if version != 1:
        raise ValueError("policy version must be 1")
    return loaded


def _required_list(document: dict[str, object], field: str) -> list[object]:
    value = document.get(field, [])
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    return value


def _parse_bounds_entry(entry: object) -> dict[str, Any]:
    mapping = _mapping(entry, "agent_bounds entry")
    _reject_extra(mapping, {"agent_id", "scopes"}, "agent_bounds entry")
    agent_id = _required_string(mapping, "agent_id")
    scopes = _required_string_list(mapping, "scopes")
    return {"agent_id": agent_id, "scopes": scopes}


def _parse_rule_entry(entry: object) -> dict[str, Any]:
    mapping = _mapping(entry, "auto_approval_rules entry")
    allowed = {
        "rule_id",
        "name",
        "target_agent_id",
        "allowed_scopes",
        "max_ttl",
        "max_ttl_seconds",
        "status",
    }
    _reject_extra(mapping, allowed, "auto_approval_rules entry")
    if "max_ttl" in mapping and "max_ttl_seconds" in mapping:
        raise ValueError("rule must not set both max_ttl and max_ttl_seconds")
    status = mapping.get("status", "active")
    if status not in {"active", "disabled"}:
        raise ValueError("rule status must be active or disabled")
    return {
        "rule_id": _optional_string(mapping, "rule_id"),
        "name": _required_string(mapping, "name"),
        "target_agent_id": _required_string(mapping, "target_agent_id"),
        "allowed_scopes": _required_string_list(mapping, "allowed_scopes"),
        "max_ttl_seconds": _duration_seconds(mapping),
        "status": status,
    }


def _parse_require_boundary(document: dict[str, object]) -> dict[str, Any]:
    raw = document.get("require_boundary")
    if raw is None:
        return {"workspace": None, "agents": []}
    mapping = _mapping(raw, "require_boundary")
    _reject_extra(mapping, {"workspace", "agents"}, "require_boundary")
    workspace: bool | None = None
    if "workspace" in mapping:
        value = mapping["workspace"]
        if not isinstance(value, bool):
            raise ValueError("require_boundary workspace must be a boolean")
        workspace = value
    agents: list[str] = []
    if "agents" in mapping:
        raw_agents = mapping["agents"]
        if not isinstance(raw_agents, list):
            raise ValueError("require_boundary agents must be a list")
        for item in raw_agents:
            if not isinstance(item, str) or item == "":
                raise ValueError("require_boundary agents must contain only non-empty strings")
            agents.append(item)
    return {"workspace": workspace, "agents": agents}


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping")
    return {str(key): item for key, item in value.items()}


def _reject_extra(mapping: dict[str, object], allowed: set[str], label: str) -> None:
    extra = sorted(set(mapping) - allowed)
    if extra:
        raise ValueError(f"unexpected {label} field: {extra[0]}")


def _required_string(mapping: dict[str, object], field: str) -> str:
    value = mapping.get(field)
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _optional_string(mapping: dict[str, object], field: str) -> str | None:
    value = mapping.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{field} must be a non-empty string when provided")
    return value


def _required_string_list(mapping: dict[str, object], field: str) -> list[str]:
    value = mapping.get(field)
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty list")
    if any(not isinstance(item, str) or item == "" for item in value):
        raise ValueError(f"{field} must contain only non-empty strings")
    return value


def _duration_seconds(mapping: dict[str, object]) -> int:
    if "max_ttl_seconds" in mapping:
        value = mapping["max_ttl_seconds"]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError("max_ttl_seconds must be a positive integer")
        return value
    raw = mapping.get("max_ttl")
    if not isinstance(raw, str) or raw == "":
        raise ValueError("rule must set max_ttl or max_ttl_seconds")
    suffix = raw[-1]
    number = raw[:-1]
    if not number.isdigit() or suffix not in {"s", "m", "h"}:
        raise ValueError(f"invalid max_ttl duration: {raw}")
    return int(number) * {"s": 1, "m": 60, "h": 3600}[suffix]


def _stable_rule_id(
    *,
    workspace_id: str,
    name: str,
    target_agent_id: str,
    scopes: tuple[str, ...],
) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "rule"
    digest = hashlib.sha256(
        "|".join((workspace_id, name, target_agent_id, ",".join(scopes))).encode("utf-8")
    ).hexdigest()[:8]
    return f"apr_{slug[:32]}_{digest}"
