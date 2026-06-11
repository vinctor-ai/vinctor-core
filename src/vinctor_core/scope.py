from __future__ import annotations

import re

ALLOWED_ACTIONS = frozenset({"read", "write", "execute", "deploy", "delete", "send"})
_RESOURCE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def attempted_scope(action: str, resource: str) -> str:
    return f"{action}:{resource}"


def is_valid_requested_action(action: str) -> bool:
    return action in ALLOWED_ACTIONS


def is_valid_requested_resource(resource: str) -> bool:
    return _is_valid_resource(resource, allow_terminal_wildcard=False)


def is_valid_grant_scope(scope: str) -> bool:
    parts = scope.split(":")
    if len(parts) != 2:
        return False

    action, resource = parts
    return is_valid_requested_action(action) and _is_valid_resource(
        resource,
        allow_terminal_wildcard=True,
    )


def match_scope(scopes: tuple[str, ...], action: str, resource: str) -> str | None:
    attempted = attempted_scope(action, resource)
    for scope in scopes:
        if scope == attempted:
            return scope
        if _matches_terminal_resource_wildcard(scope, action, resource):
            return scope
    return None


def scope_subsumes(broad_scope: str, narrow_scope: str) -> bool:
    if broad_scope == narrow_scope:
        return True
    if not is_valid_grant_scope(broad_scope) or not is_valid_grant_scope(narrow_scope):
        return False

    broad_action, _, broad_resource = broad_scope.partition(":")
    narrow_action, _, narrow_resource = narrow_scope.partition(":")
    if broad_action != narrow_action or not broad_resource.endswith("/*"):
        return False

    prefix = broad_resource.removesuffix("*")
    return narrow_resource.startswith(prefix)


def _matches_terminal_resource_wildcard(scope: str, action: str, resource: str) -> bool:
    scope_action, separator, scope_resource = scope.partition(":")
    if separator != ":" or scope_action != action:
        return False
    if not scope_resource.endswith("/*"):
        return False
    prefix = scope_resource.removesuffix("*")
    return resource.startswith(prefix)


def _is_valid_resource(resource: str, *, allow_terminal_wildcard: bool) -> bool:
    if not resource:
        return False
    if "\x00" in resource or "\\" in resource or ":" in resource:
        return False
    if resource.startswith("/") or resource.endswith("/"):
        return False

    segments = resource.split("/")
    if len(segments) < 2:
        return False
    if any(segment == "" for segment in segments):
        return False

    wildcard_segments = [index for index, segment in enumerate(segments) if "*" in segment]
    if wildcard_segments:
        return (
            allow_terminal_wildcard
            and len(wildcard_segments) == 1
            and wildcard_segments[0] == len(segments) - 1
            and segments[-1] == "*"
            and len(segments) > 1
        )

    return all(_RESOURCE_SEGMENT_RE.fullmatch(segment) is not None for segment in segments)
