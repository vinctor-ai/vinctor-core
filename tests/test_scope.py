from vinctor_core.scope import (
    attempted_scope,
    is_valid_grant_scope,
    is_valid_requested_action,
    is_valid_requested_resource,
    scope_subsumes,
)


def test_attempted_scope_preserves_raw_action_and_resource() -> None:
    assert attempted_scope("bad action", "repo/*") == "bad action:repo/*"


def test_validates_known_action_verbs() -> None:
    for action in ("read", "write", "execute", "deploy", "delete", "send"):
        assert is_valid_requested_action(action)


def test_rejects_unknown_or_malformed_action_verbs() -> None:
    for action in ("", "Read", "wirte", "write repo", "write/repo", "write\x00"):
        assert not is_valid_requested_action(action)


def test_validates_requested_resources() -> None:
    for resource in (
        "repo/feature/readme",
        "secret/env",
        "net/external/api.example.com",
        "git/push-force",
    ):
        assert is_valid_requested_resource(resource)


def test_rejects_malformed_requested_resources() -> None:
    for resource in (
        "",
        "repo",
        "/repo/readme",
        "repo/readme/",
        "repo//readme",
        "repo/read me",
        "repo\\readme",
        "repo:readme",
        "repo/*",
        "repo/readme*",
        "repo/readme\x00",
    ):
        assert not is_valid_requested_resource(resource)


def test_validates_exact_and_terminal_wildcard_grant_scopes() -> None:
    for scope in (
        "read:secret/env",
        "write:repo/feature/readme",
        "execute:git/push",
        "deploy:npm/package",
        "delete:git/reset-hard",
        "send:net/external/api.example.com",
        "write:repo/feature/*",
    ):
        assert is_valid_grant_scope(scope)


def test_scope_subsumes_exact_and_terminal_wildcards() -> None:
    assert scope_subsumes("write:repo/feature/readme", "write:repo/feature/readme")
    assert scope_subsumes("write:repo/*", "write:repo/a/b")
    assert scope_subsumes("write:repo/*", "write:repo/feature/*")
    assert scope_subsumes("write:repo/feature/*", "write:repo/feature/readme")
    assert not scope_subsumes("write:repo/feature/*", "write:repo/*")
    assert not scope_subsumes("read:repo/*", "write:repo/a/b")
    assert not scope_subsumes("write:repo/feature/readme", "write:repo/feature/other")


def test_rejects_malformed_grant_scopes() -> None:
    for scope in (
        "",
        "write",
        "write:",
        ":repo/readme",
        "write:repo",
        "write:repo:readme",
        "write:/repo/readme",
        "write:repo/readme/",
        "write:repo//readme",
        "write:repo/read me",
        "write:repo\\readme",
        "write:*",
        "write:repo*",
        "write:repo/*/readme",
        "write:repo/feature*",
        "write:repo/**",
        "*:repo/feature",
        "wirte:repo/feature",
    ):
        assert not is_valid_grant_scope(scope)
