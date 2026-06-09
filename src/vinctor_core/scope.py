from __future__ import annotations


def attempted_scope(action: str, resource: str) -> str:
    return f"{action}:{resource}"


def match_scope(scopes: tuple[str, ...], action: str, resource: str) -> str | None:
    attempted = attempted_scope(action, resource)
    for scope in scopes:
        if scope == attempted:
            return scope
        if _matches_terminal_resource_wildcard(scope, action, resource):
            return scope
    return None


def _matches_terminal_resource_wildcard(scope: str, action: str, resource: str) -> bool:
    scope_action, separator, scope_resource = scope.partition(":")
    if separator != ":" or scope_action != action:
        return False
    if not scope_resource.endswith("/*"):
        return False
    prefix = scope_resource.removesuffix("*")
    return resource.startswith(prefix)
